import json
import os
from pathlib import Path
from ..Decoration.Colors import GREEN, PURPLE, CYAN, RESET
from ..Logger.LightLogger import Logger, ErrorCode

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