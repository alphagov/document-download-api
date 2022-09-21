import json
import os


def extract_cloudfoundry_config():
    vcap_services = json.loads(os.environ["VCAP_SERVICES"])

    # Redis config - use DB 1 to separate logically from Notify - as likely to re-use the same redis instance
    os.environ["REDIS_URL"] = vcap_services["redis"][0]["credentials"]["uri"] + "/1"
