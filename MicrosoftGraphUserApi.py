import requests
import time
import sqlite3
import pyodbc
from msal import ConfidentialClientApplication
from azure.identity import ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv,find_dotenv
import os ,json
import logging
_ = load_dotenv(find_dotenv ())
class MicrosoftGraphUserApi:
    db_file_path = '/tmp/employee.db'
    def getApiToken(self):
        # Define your Azure AD and Microsoft Graph API details
        tenant_id =os.environ['_mstenant_id']
        client_id = os.environ['_msclient_id']
        #client_secret = os.environ['_msclient_secret']
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
        _hostname =   os.environ ['_dbhostname'] 
        _db_name = os.environ ['_db_name'] 
        _user_id ="edwuser"
        _driver_names = os.environ['_driver']
        sql_server_connection_string = f"DRIVER={_driver_names};SERVER={_hostname};DATABASE={_db_name};UID={_user_id};PWD={_password};TrustServerCertificate=yes"
        logging.info ("sql_server_connection_string  -->{}".format(sql_server_connection_string))
        return sql_server_connection_string

    def getAzureClient(self):
        keyVaultName =  os.environ['_vaultName']  
        KVUri = f"https://{keyVaultName}.vault.azure.net/"
        credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
        client = SecretClient(vault_url=KVUri , credential=credential)
        return client

    def __init__(self):
        self.azClient = self.getAzureClient ()
        self.access_token = self.getApiToken()
        self.sqlServerConnectionString = self.getSQLServerConnString() 
        self.data = []  # Initialize an empty list to store user details
        self.missingurl = []
        self.cleanSqlLite()

    def fetch_data(self, endpoint):
        headers = {
            "Authorization": "Bearer " + self.access_token,
            "Content-Type": "application/json"
        }
        response = requests.get(endpoint, headers=headers)
        
        if response.status_code == 200:
            data = response.json()
           
            return data
        else :
           
            raise Exception("url {} is returning code {}:".format(endpoint,response.status_code))
    
    # Function to create SQLite database and store user ids
    
    def cleanSqlLite(self):
        try :
            conn=  sqlite3.connect(self.db_file_path)
            cursor = conn.cursor()
                # SQL statement to drop a table if it exists
            cursor.execute("DROP TABLE IF EXISTS Users")
                # Create Users table
            cursor.execute('''
                        CREATE TABLE IF NOT EXISTS Users (
                            id TEXT PRIMARY KEY
                        )
                    ''')
            
                # Commit the changes
            conn.commit()
            cursor.close()
            
            logging.info("sql lite clean performed")
        except Exception as ex:
            logging.error(str(ex))
            raise

    def create_and_store_user_ids(self, users_data):
        try :
            logging.info ("inside the create_and_store_user_ids method")
            connection = sqlite3.connect(self.db_file_path)
            cursor = connection.cursor()
           
            # Insert user ids into Users table
            for user in users_data['value']:
                
                cursor.execute('''
                    INSERT OR IGNORE INTO Users
                    VALUES (?)
                ''', (user['id'],))
            logging.info ("store  ids count: {}".format(len(users_data)))
            connection.commit()
           
        except Exception as e :
            logging.error(str(e))
        finally:
             connection.close()    

    def retrieve_user_ids(self):
        logging.info ("inside the retrieve_user_ids")
        connection = sqlite3.connect(self.db_file_path)
        cursor = connection.cursor()

        cursor.execute('SELECT id FROM Users')
        user_ids = [row[0] for row in cursor.fetchall()]

        connection.close()
        logging.info ("retrieved  ids count: {}".format(len(user_ids)))
        return user_ids

    
    
    def batch_insert_from_rest(self,  batch_size=1000):
        logging.info ("inside batch_insert_from_rest")
        conn = pyodbc.connect(self.sqlServerConnectionString)
            # Create a cursor
        cursor = conn.cursor()
        table_name = "[dbo].[AD_Colleagues_Staging]"
        try:
             # Execute the truncate query before insert
            cursor.execute(f"TRUNCATE TABLE {table_name}")
            # Commit the changes
            conn.commit()
            logging.info ("Truncate completed  ->{}".format(table_name))

            insert_query = '''INSERT  INTO [dbo].[AD_Colleagues_Staging](
                [id], [displayName], [givenName], [mail], [surname],
                [userPrincipalName], [aboutMe], [birthday], [businessPhones],
                [city], [companyName], [country], [department], [employeeId],
                [faxNumber], [hireDate], [imAddresses], [interests], [jobTitle],
                [mailNickname], [mobilePhone], [mySite], [officeLocation],
                [onPremisesExtensionAttributes], [onPremisesDistinguishedName],
                [onPremisesDomainName], [onPremisesImmutableId],
                [onPremisesUserPrincipalName], [otherMails], [pastProjects],
                [postalCode], [preferredDataLocation], [preferredLanguage],
                [preferredName], [responsibilities], [schools], [skills],
                [state], [streetAddress], [usageLocation], [userType],
                [onPremisesSamAccountName], [accountEnabled], [createdDateTime],
                [manager],[dw_created_dtm], [dw_created_by])
                VALUES (
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?,
                  ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, GETDATE(), SYSTEM_USER
               ) '''

            # Initialize batch counter and batch data
            batch_counter = 0
            batch_data = []
            # Process each record from the REST data
            logging.info("data count for batch insert {}".format(len(self.data)))
            for user_details_data in self.data:
                on_premises_dn = user_details_data.get('onPremisesDistinguishedName')
                formatted_dn =  '' if on_premises_dn is None else on_premises_dn
                on_premises_ea = user_details_data.get('onPremisesExtensionAttributes')
                formatted_ea =  '' if on_premises_ea is None else json.dumps(on_premises_ea)
                on_prmises_dmn =user_details_data.get('onPremisesDomainName')
                formatted_dmn = '' if on_prmises_dmn is None else on_prmises_dmn
                on_premises_pn= user_details_data.get('onPremisesUserPrincipalName')
                formatted_pn=  '' if on_premises_pn is None else on_premises_pn
                on_premises_imm_id = user_details_data.get('onPremisesImmutableId')
                formatted_imm_id =  '' if on_premises_imm_id is None else on_premises_imm_id
                batch_data.append((
                    user_details_data['id'],
                    user_details_data.get('displayName', ''),
                    user_details_data.get('givenName', ''),
                    user_details_data.get('mail', ''),
                    user_details_data.get('surname', ''),
                    user_details_data.get('userPrincipalName', ''),
                    user_details_data.get('aboutMe', ''),
                    user_details_data.get('birthday', ''),
                    next(iter(user_details_data.get('businessPhones', [])), ''),
                    user_details_data.get('city', ''),
                    user_details_data.get('companyName', ''),
                    user_details_data.get('country', ''),
                    user_details_data.get('department', ''),
                    user_details_data.get('employeeId', ''),
                    user_details_data.get('faxNumber', ''),
                    user_details_data.get('hireDate', ''),
                    next(iter(user_details_data.get('imAddresses', [])), ''),
                    next(iter(user_details_data.get('interests', [])), ''),
                    user_details_data.get('jobTitle', ''),
                    user_details_data.get('mailNickname', ''),
                    user_details_data.get('mobilePhone', ''),
                    user_details_data.get('mySite', ''),
                    user_details_data.get('officeLocation', ''),
                    formatted_ea,
                    formatted_dn,
                    formatted_dmn,
                    formatted_imm_id,
                    formatted_pn,
                    next(iter(user_details_data.get('otherMails', [])), ''),
                    next(iter(user_details_data.get('pastProjects', [])), ''),
                    user_details_data.get('postalCode',''),
                    user_details_data.get('preferredDataLocation',''),
                    user_details_data.get('preferredLanguage',''),
                    user_details_data.get('preferredName',''),
                    next(iter(user_details_data.get('responsibilities', [])), ''),
                    next(iter(user_details_data.get('schools', [])), ''),
                    next(iter(user_details_data.get('skills', [])), ''),
                    user_details_data.get('state',''),
                    user_details_data.get('streetAddress',''),
                    user_details_data.get('usageLocation',''),
                    user_details_data.get('userType',''),
                    user_details_data.get('onPremisesSamAccountName',''),
                    user_details_data.get('accountEnabled',''),
                    user_details_data.get('createdDateTime',''),
                    user_details_data.get('manager','')
                    ))
                batch_counter += 1
               
                # Execute batch insert when batch size is reached
                if batch_counter % batch_size == 0:
                    cursor.executemany(insert_query, batch_data)
                    conn.commit()
                    logging.info("batch_counter --->{}".format(batch_counter))
                    batch_data = []

            # Insert any remaining data
            if batch_data:
                cursor.executemany(insert_query, batch_data)
                conn.commit()
                batch_data = []

            logging.info(f"Data from REST endpoint inserted into table using batch insert.")

        except pyodbc.Error as e:
            print(f"Error occurred: {e}")
            logging.error(str(e))
            raise
        except Exception as ex:
            logging.error(str(ex))
            raise    
        finally:
            # Close the cursor and connection
            cursor.close()
            conn.close()

   
    def extract_pagination_link(self, response):
        return response.get('@odata.nextLink', None)
    

    def parseAndExtractUserIds(self):
        logging.info("inside the parseAndExtractUserIds")
        users_endpoint = "https://graph.microsoft.com/v1.0/users"
        #fetch the data from the first end point

        initial_users_data = self.fetch_data(users_endpoint)
        # Extract user ids and store in SQLite database
        self.create_and_store_user_ids(initial_users_data)
        # Extract pagination link and fetch additional data if available
        pagination_link = self.extract_pagination_link(initial_users_data)
        link =0
        while pagination_link:
            link = link +1
            print ("extracting data for user pagination link no {} -->{} ".format(link, pagination_link))
            #fetch data from pagination_link
            additional_users_data = self.fetch_data(pagination_link)
            self.create_and_store_user_ids(additional_users_data)
            # Extract next pagination link
            pagination_link = self.extract_pagination_link(additional_users_data)
            #for testing purpose only
        print("All User ids has been stored in the SQL Lite database.")

   
    def process_user(self, user_id):
        user_details_endpoint_woith_id = f"https://graph.microsoft.com/v1.0/users/{user_id}/?$select=id,displayName,givenName,mail,surname,userPrincipalName,id,aboutMe,birthday,"+\
                                          "businessPhones,city,companyName,country,department,employeeId,faxNumber,hireDate,imAddresses,interests,jobTitle,mailNickname,mobilePhone,"+\
                                           "mySite,officeLocation,onPremisesExtensionAttributes,onPremisesDistinguishedName,onPremisesDomainName,onPremisesImmutableId,onPremisesUserPrincipalName,"+\
                                           "otherMails,pastProjects,postalCode,preferredDataLocation,preferredLanguage,preferredName,responsibilities,schools,skills,state,streetAddress,usageLocation,"+\
                                            "userType,onPremisesSamAccountName,accountEnabled,createdDateTime,manager"
        user_detail = self.fetch_data(user_details_endpoint_woith_id)
        if user_detail and user_detail.get('id'):
            self.data.append (user_detail)
        else :
            self.missingurl.append(user_details_endpoint_woith_id)
            

        

    def fetch_and_store_user_data(self, stored_user_ids):
        with ThreadPoolExecutor(max_workers=6) as executor:
            executor.map(self.process_user, stored_user_ids)

    def retrieveIdsAndStoreResultSQLServerDB(self):
        stored_user_ids = self.retrieve_user_ids()
        self.fetch_and_store_user_data (stored_user_ids)
        logging.info("stored user id detail count-> {}".format(len(self.data)))
        self.batch_insert_from_rest()
        logging.info("batch insert completed with missing count {} url ".format(len(self.missingurl)))


if  __name__ == "__main__":
    start_time = time.time()
    graph_api_manager = MicrosoftGraphUserApi()
    #extract user id from all pagination link 
    graph_api_manager.parseAndExtractUserIds()
    graph_api_manager.retrieveIdsAndStoreResultSQLServerDB()

    end_time = time.time()
    total_time = end_time - start_time
    # Print the total time in seconds
    print(f"Total time taken: {total_time:.2f} seconds")


