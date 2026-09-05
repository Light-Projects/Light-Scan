import os

def download_zip():
    try:
        os.system('git clone https://github.com/Light-Projects/LSSE-DB')

        try:
            os.rename('LSSE', 'LSSE_old')
            print("Directory renamed successfully.")
        except FileNotFoundError:
            print("Error: The source directory was not found.")
        except FileExistsError:
            print("Error: A directory with the new name already exists.")

        old_name = "LSSE-DB"
        new_name = "LSSE"

        try:
            os.rename(old_name, new_name)
            print("Directory renamed successfully.")
        except FileNotFoundError:
            print("Error: The source directory was not found.")
        except FileExistsError:
            print("Error: A directory with the new name already exists.")

        print(f"Successfully downloaded LSSE database.")
    except:
        print(f"[!] Error while downloading LSSE database.")
