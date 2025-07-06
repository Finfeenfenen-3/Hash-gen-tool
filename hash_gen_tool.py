import sys
import hashlib

print("Welcome to the:")
print(r""" 
    __               __                           __              __
   / /_  ____ ______/ /_     ____ ____  ____     / /_____  ____  / /
  / __ \/ __ `/ ___/ __ \   / __ `/ _ \/ __ \   / __/ __ \/ __ \/ /
 / / / / /_/ (__  ) / / /  / /_/ /  __/ / / /  / /_/ /_/ / /_/ / /
/_/ /_/\__,_/____/_/ /_/   \__, /\___/_/ /_/   \__/\____/\____/_/
                          /____/
""")
print("version: 1.3")
print("by felin_3")

hashes = []

def exit_app():
    sys.exit()

def generate_hash_table():
    input_file = input("Enter input file name:\n")
    output_file = input("Enter output file name (leave empty to auto-create):\n")
    
    if not output_file:
        output_file = "hashout.txt"

    def md5(data):
        return hashlib.md5(data.encode()).hexdigest()

    def sha256(data):
        return hashlib.sha256(data.encode()).hexdigest()

    def sha3_512(data):
        return hashlib.sha3_512(data.encode()).hexdigest()

    try:
        with open(input_file, "r") as file:
            for line in file:
                clean_line = line.strip()
                print(f"Processing line: '{clean_line}'")
                hash_choice = int(input("Choose hash type:\n1: MD5\n2: SHA256\n3: SHA3-512\n"))
                
                hash_func = {
                    1: md5,
                    2: sha256,
                    3: sha3_512
                }.get(hash_choice)
                
                if not hash_func:
                    print("Invalid choice. Please choose 1, 2, or 3.")
                    return
                
                hashes.append(hash_func(clean_line) + "\n")
        
        with open(output_file, "w") as out_file:
            out_file.writelines(hashes)
            print(f"Hash table saved to {output_file}\n")
            main()
    except Exception as e:
        print(f"Error: {e}")
        main()

actions = {
    0: exit_app,
    1: generate_hash_table
}

def main():
    choice = int(input("Select an option:\n0: Exit\n1: Generate hash table\n"))
    actions.get(choice, lambda: None)()

if __name__ == "__main__":
    main()
