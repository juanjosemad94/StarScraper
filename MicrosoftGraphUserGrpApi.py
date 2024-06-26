import requests
import time
import sqlite3
import pyodbc
from msal import ConfidentialClientApplication
from azure.identity import DefaultAzureCredential
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv,find_dotenv
import logging
import os
_ = load_dotenv(find_dotenv ())
class MicrosoftGraphUserGrpApi:
    db_file_path = '/tmp/employeeGroup.db'
    def getApiToken(self):
        # Define your Azure AD and Microsoft Graph API details
        tenant_id =os.environ['_mstenant_id']
        client_id = os.environ['_msclient_id']
        client_secret = self.azClient.get_secret("ADGraphsecret").value
        authority = f"https://login.microsoftonline.com/{tenant_id}"
        app = ConfidentialClientApplication(
            client_id,
            authority=authority,
            client_credential=client_secret
        )
        token_response = app.acquire_token_for_client(scopes=["https://graph.microsoft.com/.default"])

        # Get the access token from the token response
        access_token = token_response["access_token"]
        return access_token
    
    def getSQLServerConnString(self):
        _password = self.azClient.get_secret("trg-sql-edw-pwd").value
        _hostname =  os.environ ['_dbhostname'] #"HC-AZ-DEV-SQL"
        _db_name = os.environ ['_db_name']
        _user_id ="edwuser"
        _driver_names = os.environ['_driver']
        sql_server_connection_string = f"DRIVER={_driver_names};SERVER={_hostname};DATABASE={_db_name};UID={_user_id};PWD={_password};TrustServerCertificate=yes"
        logging.info ("sql_server_connection_string -->{}".format (sql_server_connection_string))
        return sql_server_connection_string

    def getAzureClient(self):
        keyVaultName =   os.environ['_vaultName'] 
        KVUri = f"https://{keyVaultName}.vault.azure.net/"
        #credential = DefaultAzureCredential(additionally_allowed_tenants=["*"])
        credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
        client = SecretClient(vault_url=KVUri , credential=credential)
        return client

    def __init__(self):
        self.azClient = self.getAzureClient ()
        self.access_token = self.getApiToken()
        self.db_file_path = self.db_file_path 
        self.data = []  # Initialize an empty list to store user details
        self.sqlServerConnectionString = self.getSQLServerConnString()        
        self.sqlLiteClean()
    def fetch_data(self, endpoint):
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        response = requests.get(endpoint, headers=headers)
        return response.json()
    
    # Function to create SQLite database and store user ids
    def sqlLiteClean(self):

        conn = sqlite3.connect(self.db_file_path)
        cursor = conn.cursor()
        cursor.execute("DROP TABLE IF EXISTS Users")
            # Create Users table

        # Create Users table
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS Users (
                id TEXT PRIMARY KEY,
                displayName TEXT   
            )
        ''')
        
        return conn,cursor
    def create_and_store_user_ids(self, users_data):
        try :
            
            connection = sqlite3.connect(self.db_file_path)
            cursor = connection.cursor()


            # Insert user ids into Users table
            for user in users_data['value']:
                logging.info ("storing user id: {}".format(user['id']))
                cursor.execute('''
                    INSERT OR IGNORE INTO Users
                    VALUES (? , ?)
                ''', (user['id'],user['displayName']))

            connection.commit()
            connection.close()
            
        except Exception as ex:
            logging.error(str(ex))
            raise
    

    def retrieve_user_ids(self):
        connection = sqlite3.connect(self.db_file_path)
        cursor = connection.cursor()

        cursor.execute('SELECT id, displayName FROM Users')
        user_tuples = [(row[0], row[1]) for row in cursor.fetchall()]

        connection.close()
        return user_tuples

    
    
    def batch_insert_from_rest(self, batch_size=1000):
        conn = pyodbc.connect(self.sqlServerConnectionString)
            # Create a cursor[USER_GROUP_Staging]
        cursor = conn.cursor()
        table_name = "[dbo].[USER_GROUP_Staging]"
        try:
             # Execute the truncate query before insert
            cursor.execute(f"TRUNCATE TABLE {table_name}")
            # Commit the changes
            conn.commit()
            logging.info ("Truncate completed  ->{}".format(table_name))
            insert_query = '''INSERT  INTO '''+table_name +'''(
                [UserID], [SAMACCOUNTNAME], [MEMBEROF], [dw_created_dtm], [dw_created_by])
                VALUES (
                  ?, ?, ?, GETDATE(), SYSTEM_USER
               ) '''

            # Initialize batch counter and batch data
            batch_counter = 0
            batch_data = []
            # Process each record from the REST data
            for user_details_data in self.data:
                batch_data.append(user_details_data)
                batch_counter += 1
                # Execute batch insert when batch size is reached
                if batch_counter % batch_size == 0:
                    cursor.executemany(insert_query, batch_data)
                    conn.commit()
                    batch_data = []

            # Insert any remaining data
            if batch_data:
                cursor.executemany(insert_query, batch_data)
                conn.commit()

            print(f"Data from REST endpoint inserted into table using batch insert.")

        except pyodbc.Error as e:
            logging.error(str(e))

        finally:
            # Close the cursor and connection
            cursor.close()
            conn.close()


   

    def extract_pagination_link(self, response):
        return response.get('@odata.nextLink', None)
    

    def parseAndExtractUserIds(self):
        logging.info("Inside the  method")
        users_endpoint = "https://graph.microsoft.com/v1.0/users"
        #fetch the data from the first end point
        initial_users_data = self.fetch_data(users_endpoint)
        # Extract user ids , display name and store in SQLite database
        self.create_and_store_user_ids(initial_users_data)
        # Extract pagination link and fetch additional data if available
        pagination_link = self.extract_pagination_link(initial_users_data)
        link =0
        while pagination_link:
            link = link +1
            print ("extracting data for pagination link no {} -->{} ".format(link, pagination_link))
            #fetch data from pagination_link
            additional_users_data = self.fetch_data(pagination_link)
            self.create_and_store_user_ids(additional_users_data)
            # Extract next pagination link
            pagination_link = self.extract_pagination_link(additional_users_data)
            #break #for testing purpose only
        print("All User ids has been stored in the SQL Lite database.")

   
    def process_user(self, user_tuple):
        user_details_endpoint_with_id= f"https://graph.microsoft.com/v1.0/users/{user_tuple[0]}/memberOf?$select=displayName&$top=999"
        user_grp_data = self.fetch_data(user_details_endpoint_with_id)
        if user_grp_data:
            logging.info(f"\nStoring the result for user id: {user_tuple[0]}")
            for item in user_grp_data["value"]:
                self.data.append((user_tuple[0], user_tuple[1], item["displayName"]))

    def fetch_and_store_user_data(self, stored_user_info):
        with ThreadPoolExecutor(max_workers=10) as executor:
             executor.map(self.process_user, stored_user_info)
        # for item in stored_user_info:
        #     self.process_user(item)
        #     break #need to remove
        
    def retrieveIdsAndStoreResultSQLServerDB(self):
        stored_user_tuples_lst = self.retrieve_user_ids()
        logging.info("total user id  --> {} ".format(len(stored_user_tuples_lst)))
        self.fetch_and_store_user_data (stored_user_tuples_lst)
      
        print("Now performing batch insert for each user detail")
        self.batch_insert_from_rest()
        print("batch insert has been completed")

if  __name__ == "__main__":
    start_time = time.time()
    graph_api_manager = MicrosoftGraphUserGrpApi()
    #extract user id from all pagination link 
    graph_api_manager.parseAndExtractUserIds()
    graph_api_manager.retrieveIdsAndStoreResultSQLServerDB()
    end_time = time.time()
    total_time = end_time - start_time
    # Print the total time in seconds
    print(f"Total time taken: {total_time:.2f} seconds")


