from azure.identity import ClientSecretCredential
from dotenv import load_dotenv, find_dotenv
import logging
from azure.storage.blob import BlobServiceClient
from azure.keyvault.secrets import SecretClient
import os, json, pandas as pd, requests
from datetime import datetime
from urllib.parse import urljoin
_ = load_dotenv(find_dotenv ())

class HRS:

    def getAzureClient(self):
        keyVaultName =  os.environ['_vaultName']  
        KVUri = f"https://{keyVaultName}.vault.azure.net/"
        credential = ClientSecretCredential(os.environ["_tenant_id"], os.environ["_client_id"], os.environ["_client_secret"])
        client = SecretClient(vault_url=KVUri , credential=credential)
        return client
     
    def __init__(self):
        self.azClient = self.getAzureClient ()
        self.base_url = "https://reporting-api.hrsanchor.com"
          
    def send_request(self,data, service, START_DATE, END_DATE ) -> str:
        logging.info('inside the send_request method')
        data['START_DATE'] =START_DATE
        data['END_DATE'] = END_DATE
        endpoint_url = urljoin(self.base_url, service)
        # Set the headers for the request
        headers = {"Content-Type": "application/json"}
        # Send the GET request to the parametrized endpoint
        logging.info('web sevice {} is getting called   {} {}'.format(endpoint_url, START_DATE, END_DATE))
        response = requests.request(method = 'get', url = endpoint_url, data = json.dumps(data), headers = headers) 
        logging.info('web sevice {} is  called   {} {}'.format(endpoint_url, START_DATE, END_DATE))
        # Check if the request was successful (HTTP status code 200)
        if response.status_code == 200:
            logging.info('web sevice returned successful result')
            blob_client= self.write_to_blob(service, response.text)
            logging.info('writing to the blob container sucessful')
            # Check if writing to Azure container was successful
            if blob_client.exists() :
                return f"Request successful. Result written to Azure container."
            else:
                return  f"Error writing result to Azure container: {response.text}"
        else:
            logging.error( response.text)
            self.write_err_to_blob(service, response.text)
            raise Exception (f" {response.text} ")

    def getAzBlobClient(self):
        blob_service_client = None
        try :
           
            azure_container_url =self.azClient.get_secret("azure-storage-connection-string").value
            # Create a BlobServiceClient
            blob_service_client = BlobServiceClient.from_connection_string(azure_container_url)
            print ("returning from Az Blob Client--> {}".format(azure_container_url))
            return blob_service_client
        except Exception as e:
            logging.error(f"Error: {e}")
            return blob_service_client

    def write_err_to_blob(self,service, content):

        blob_service_client = self.getAzBlobClient()    
        containername = "dex/INB/HRS/err"
        if blob_service_client:
            current_date = datetime.today().strftime("%Y%m%d")    
            filanme =  f"{service} {current_date}.json"
        
            # Create a ContainerClient
            try:
                container_client = blob_service_client.get_container_client(containername)
                blob_client = container_client.get_blob_client(filanme)
                blob_client.upload_blob(content, overwrite=True)
                logging.info("Error uploaded")
                return blob_client
            except Exception as e:
                logging.error( str(e))
                pass

        else:
            return blob_service_client
        
    def write_to_blob(self,service, content):

        blob_service_client = self.getAzBlobClient()    
        containername = "dex/INB/HRS"
        current_date = datetime.today().strftime("%Y%m%d")    
        filanme =  f"{service} {current_date}.csv"
        logging.info('writing to the blob container')
        # Create a ContainerClient
        container_client = blob_service_client.get_container_client(containername)
        blob_client = container_client.get_blob_client(filanme)
        data = json.loads(content) 
        json_data = data['data'] 
        df = pd.DataFrame.from_dict(json_data, orient='index') 
        # covert to the dataframe
        csv_content = df.to_csv (index= False)
        # Upload content to the blob
        blob_client.upload_blob(csv_content, overwrite=True)
        return blob_client
    


if __name__ == '__main__':
        data = { 
        "workbook": "Population Reports", 
        "SUBGROUP": "SUBGROUP_ALL", 
        "Token_name": "compassus_token", 
        "secret_token": "j9ZhHVS6RNqtTPWaFfiA7g==:haAjDIp3T0lI88XKmtZ1rcBidfO9XlfJ", 
        "site": "CompassusAPI", 
        "CLIENT": "Compassus", 
        "START_DATE" : "2024-03-01", 
        "END_DATE" : "2024-03-02" 
        
        } 

        data_json = json.dumps(data) 

        headers = {'content-type': 'application/json'} 

        URL = 'https://reporting-api.hrsanchor.com/enrollments' 

        hrs = HRS()
        print (hrs.azClient.get_secret("hrs-secret-token").value)
        frmDate = '2024-05-07'
        toDate = '2024-05-07'
        try :
            responsetxt = hrs.send_request (data, "enrollments", frmDate, toDate)
            print (responsetxt) 
        except Exception as ex:
            print (str(ex))
        
        
        
       