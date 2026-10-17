# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.

import json
import os
from pathlib import Path
from LightPacket.Decoration.Colors import GREEN, CYAN, RESET,PURPLE
from LightPacket.Logger.LightLogger import ErrorCode, Logger

logger = Logger()

def ls(proto = None):
    if proto == None:
        protos = os.listdir(str(Path(__file__).parent) + "/protos")
        print()
        for file in protos:
            with open(str(Path(__file__).parent) + f"/protos/{file}", "r", encoding="utf-8") as f:
                data = json.loads(f.read())
                fields = data["Proto"]["Fields"]

            print(f"[- {GREEN}{data['Proto']['Name']}{RESET} -]")
            for field in fields:
                print(f"{CYAN}* {field}{RESET}")
            print()
        print(f"{GREEN}[+] Total Protos Count : {PURPLE}{len(protos)}{RESET}\n")
    else:
        try:
            print()
            if type(proto) == str:
                pass
            else:
                proto = str(proto).replace("<","").replace(">","").replace("'","").replace("class","").strip().split(".")[2]
            with open(str(Path(__file__).parent) + f"/protos/{proto}.json", "r", encoding="utf-8") as f:
                data = json.loads(f.read())
                fields = data["Proto"]["Fields"]

            print(f"[- {GREEN}{data['Proto']['Name']}{RESET} -]")
            for field in fields:
                print(f"{CYAN}* {field}{RESET}")
            print()
        except:
            logger.error(error_code=ErrorCode.NOT_FOUND,message=f"{proto} do not exist in LightPacket protos")

def protos_count():
    return len(os.listdir(str(Path(__file__).parent) + "/protos"))