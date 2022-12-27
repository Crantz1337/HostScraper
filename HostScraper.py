from typing import Any, Generator

import shodan
import json
import os.path

api = shodan.Shodan("Token")  # Account token
query = 'port:80 WWW-Authenticate: Basic realm='  # What shodan will search for

info = api.info()

filePath = r"C:\Users\user\Desktop\targets\targs.txt"  # Where to write results
port_arr = ["80"] # Which port/s the service is on

if __name__ == '__main__':

    # Check if filepath is valid
    exists = os.path.isfile(filePath)
    if exists == False:
        open(filePath, "x")  # Creates file

    f = open(filePath, "w")

    # Query and return array of result objects, each representing a host.
    result = api.search_cursor(query)

    total = api.count(query)
    maxCount = total["total"]  # how many hosts we want
    count = 0

    for info in result:
        try:
            if count == maxCount:
                break
            f.write(info["ip_str"] + " ")
            f.write(json.dumps(port_arr) + '\n')
            count += 1
            print("{} / {} / (total) {}".format(count, maxCount, total["total"]))
        except shodan.exception.APIError:
            continue


f.close()
print("Done!")
