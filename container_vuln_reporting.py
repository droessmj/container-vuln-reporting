from datetime import datetime, timedelta, timezone
from laceworksdk import LaceworkClient

import argparse
import logging
import json

MAX_RESULT_SET = 500_000
MID_CLUSTER_MAP = {}
IMAGEID_VULN_MAP = {}

class OutputRecord():
    def __init__(self, image_id, vuln_list, active_count):
        self.image_id = image_id
        self.vuln_list = vuln_list
        self.active_count = active_count
        self.critical_count = 0
        self.high_count = 0
        self.medium_count = 0
        self.low_count = 0
        self.info_count = 0

        for v in vuln_list:
            if v['severity'].lower() == 'critical':
                self.critical_count += 1
            elif v['severity'].lower() == 'high':
                self.high_count += 1 
            elif v['severity'].lower() == 'medium':
                self.medium_count += 1
            elif v['severity'].lower() == 'low':
                self.low_count += 1
            elif v['severity'].lower() == 'info':
                self.low_count += 1
        
        self.total_fixes = self.critical_count + self.high_count + self.medium_count + self.low_count + self.info_count

        self.cluster = MID_CLUSTER_MAP[image_id['mid']]

    def printCsvRow(self):
       print(f'{self.cluster},{self.image_id["repo"]},{self.image_id["tag"]},{self.critical_count},{self.high_count},{self.medium_count},{self.low_count},{self.info_count},{self.active_count},{self.image_id["imageId"]},{self.image_id["imageCreatedTime"]},{self.image_id["size"]}, {self.total_fixes}') 

    def __eq__(self,other):
        return (self.image_id['imageId'] == other.image_id['imageId']
                and self.vuln_list == other.vuln_list
                and self.active_count == other.active_count
                and self.cluster == other.cluster)

    def __hash__(self):
        t = (self.image_id['imageId'], self.cluster, self.total_fixes, self.image_id['tag'])
        return hash(t)

def main(args):
    set_csv_rows = set()

    # lookback time can be configured for any value between 1 hour and 7 days
    current_time = datetime.now(timezone.utc)
    start_time = current_time - timedelta(days=7)
    start_time = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")
    end_time = current_time.strftime("%Y-%m-%dT%H:%M:%SZ")

    # check the SDK docs for other options when instantiating a LaceworkClient
    client = LaceworkClient(profile=args.profile)

    distinct_mids = set()
    distinct_imageId_objs = set()
    distinct_imageIds = set()
    active_images = {}

    machines = client.entities.machines.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters":[
                {
                    "field":"machineTags.Account",
                    "expression":"eq",
                    "value":args.account
                }
            ]
        })

    for i in machines:
        for c in i['data']:
            if 'aws:eks:cluster-name' in c['machineTags']:
                MID_CLUSTER_MAP[c['mid']] = c['machineTags']['aws:eks:cluster-name']
            distinct_mids.add(c['mid'])

    all_active_images = client.entities.images.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters":[
                {
                    "field":"mid",
                    "expression":"in",
                    "values": list(distinct_mids)
                }
            ],
            "returns":[
                    "imageCreatedTime","imageId","repo","size","tag","mid"
                ]
        })

    for i in all_active_images:
        for c in i['data']:
            distinct_imageId_objs.add(json.dumps(c))
            distinct_imageIds.add(c["imageId"])
            if c['imageId'] in active_images:
                active_images[c['imageId']] += 1
            else:
                active_images[c['imageId']] = 1


    all_container_vulns = client.vulnerabilities.containers.search(json={
            "timeFilter": {
                "startTime": start_time,
                "endTime": end_time
            },
            "filters":[
                {
                    "field":"imageId",
                    "expression":"in",
                    "values":list(distinct_imageIds)
                },
                {
                    "field":"status",
                    "expression":"not_in",
                    "values": ["EXCEPTION","GOOD"]
                }
            ],
             "returns":[
                "vulnId","status","severity","imageId"
            ]
        })
    

    for r in all_container_vulns:
        for v in r['data']:
            if v['imageId'] in IMAGEID_VULN_MAP:
                IMAGEID_VULN_MAP[v['imageId']].append(v)
            else:
                IMAGEID_VULN_MAP[v['imageId']] = [v]

    for image_info in distinct_imageId_objs:
        image_info = json.loads(image_info)

        active_count = active_images[image_info['imageId']]
        
        lookup_results = IMAGEID_VULN_MAP[image_info['imageId']] if image_info['imageId'] in IMAGEID_VULN_MAP else list()
        #dedupe vuln results per image
        lookup_results = [dict(t) for t in {tuple(d.items()) for d in lookup_results}]
        set_csv_rows.add(OutputRecord(image_info,lookup_results,active_count))
    

    # Print CSV Headers
    print('Cluster,Repository,Image Tags,Critical,High,Medium,Low,Info,Active Count,ImageId,Image Created Time,Image Size,Number Fixes')
    for r in set_csv_rows:
        r.printCsvRow()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='A script to automatically issue container vulnerability scans to Lacework based on running containers'
    )
    parser.add_argument(
        '-p', '--profile',
        default='default',
        help='The Lacework CLI profile to use'
    )
    parser.add_argument(
        '-a', '--account',
        default='default',
        help='The account to target for machines running the images of interest'
    )

    args = parser.parse_args()
    main(args)