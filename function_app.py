import azure.durable_functions as df
import azure.functions as func
import logging
from  MicrosoftGraphUserApi  import MicrosoftGraphUserApi
from MicrosoftGraphUserGrpApi  import MicrosoftGraphUserGrpApi
from MicrosoftGraphUserMgrApi import  MicrosoftGraphUserMgrApi
from multiprocessing import Process
from HRS import HRS

# Load environment variables from .env
from SHPEpisode import run_shpEpisode, combine_output
from SHPRating import  run_ratingSpider


dapp = df.DFApp(http_auth_level=func.AuthLevel.ANONYMOUS)
#app = func.FunctionApp(http_auth_level=func.AuthLevel.ANONYMOUS)

@dapp.route(route="orchestrators/{functionName}")
@dapp.durable_client_input(client_name="client")
async def http_start(req: func.HttpRequest, client):
    function_name = req.route_params.get('functionName')
    logging.info ("function_name .. {}".format(function_name))
    instance_id = await client.start_new(function_name, None)  # Pass the functionName here
    logging.info ("instance_id ....{}".format(instance_id))
    response = client.create_check_status_response(req, instance_id)
    return response

# Orchestrator
@dapp.orchestration_trigger(context_name="context")
def azure_orchestrator(context):
    results = []
    # Call the first activity 
    result1 = yield context.call_activity("process_user", None)
    # Process each name sequentially using the second activity
    result2 = yield context.call_activity("process_usergroup", None)
    result3 = yield context.call_activity("process_userManager", None)
    results.append(result1)
    results.append(result2)
    results.append(result3)
    logging.info ("completed graphapi_orchestrator ")
    return results



@dapp.activity_trigger(input_name="dummy")
def process_usergroup(dummy: str):
    logging.info('user grp api invoked')
    grp  =  MicrosoftGraphUserGrpApi ()
    grp.parseAndExtractUserIds()
    grp.retrieveIdsAndStoreResultSQLServerDB()
    return f"completed user group processing"
   


@dapp.activity_trigger(input_name="dummy")
def process_user(dummy: str):
    logging.info ("user api invoked ")
    user = MicrosoftGraphUserApi ()
    #extract user id from all pagination link 
    user.parseAndExtractUserIds()
    user.retrieveIdsAndStoreResultSQLServerDB()
    logging.info ("user api   completed")
    return f"completed user processing"


@dapp.activity_trigger(input_name="dummy")
def process_userManager(dummy: str):
    logging.info ("user api invoked ")
    mgr = MicrosoftGraphUserMgrApi ()
    #extract user id from all pagination link 
    mgr.parseAndExtractUserIds()
    mgr.retrieveIdsAndStoreResultSQLServerDB()
    logging.info ("user manager api completed")
    return f"user manager api completed"


@dapp.route(route="hrs")
def hrs(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('HRS HTTP trigger function processed a request.')
    frmDate = req.params.get('fromDate')
    toDate = req.params.get('toDate')
    suffix = req.params.get("service")
    logging.info("HRS HTTP trigger function processed a request with -->{} {} {}".format(frmDate,toDate, suffix ))
    if frmDate and toDate  and suffix:
        hrs = HRS()
        data = { 

            "workbook": "Population Reports", 
            "SUBGROUP": "SUBGROUP_ALL", 
            "Token_name": "compassus_token", 
            "secret_token": hrs.azClient.get_secret("hrs-secret-token").value, 
            "site": "CompassusAPI", 
            "CLIENT": "Compassus", 
            "START_DATE" : "<<>>", 
            "END_DATE" : "<<>>", 
            "Metrics":"BloodPressure" 

        } 
        
       
       
        responsetxt = hrs.send_request (data,suffix, frmDate, toDate)
        try :
             
                return func.HttpResponse(
                        responsetxt,
                        status_code=200
                )
        except Exception as exp:
              return func.HttpResponse(
                        str(exp),
                        status_code=200
                )
    
    else:
       
       return func.HttpResponse(
                "Either fromDate, toDate or service  is missing in requestes parameter",
                status_code=200
        )  

@dapp.route(route="episode")
def episode(req: func.HttpRequest) -> func.HttpResponse:
        process = Process(target=run_shpEpisode)
        process.start()
        process.join()
        combine_output()
        logging.info ("Crwaling completed for episode report")
        return func.HttpResponse(f"This HTTP triggered function executed successfully.")

@dapp.route(route="starrating")
def starrating(req: func.HttpRequest) -> func.HttpResponse:
       
        process = Process(target=run_ratingSpider)
        process.start()
        process.join()
        logging.info ("Crwaling completed for startrating report")
        return func.HttpResponse(f"This HTTP triggered function executed successfully.")



