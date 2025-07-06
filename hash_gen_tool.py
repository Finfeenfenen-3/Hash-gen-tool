import hashlib
import sys

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
hashs = []
def exit():
    sys.exit()
def generate_hash_table():
    inputfile = input("print input_file;\n")
    outputfile = input("print output_file(if none auto create outfile);\n")
    if not outputfile:
        outputfile = "hashout.txt"
    def md5(data):
            hash = hashlib.md5(data.encode()).hexdigest()
            return hash
    def sha256(data):
        hash = hashlib.sha256(data.encode()).hexdigest()
        return hash
    def sha3_512(data):
        hash = hashlib.sha3_512(data.encode()).hexdigest()
        return hash
    with open(inputfile, "r") as file:
        for line in file:
            clean_line = line.strip()
            hash_choice = int(input("1:md5 hash\n2:sha256 hash\n3:sha3_512 hash\n"))
            hash_func = {
                1: md5,
                2: sha256,
                3: sha3_512
            }.get(hash_choice)
            if not hash_func:
                print("Invalid hash choice")
                return
            hashs.append(hash_func(clean_line) + "\n")
    with open(outputfile, "w") as output_file:
        output_file.writelines(hashs)
        print("done\n")
        main()
    actions_2 = {
    1:md5,
    2:sha256,
    3:sha3_512
}

actions = {
    0:exit,
    1:generate_hash_table
}

def main():
    choise = int(input("0: exit\n1: generate_hash_table\n"))
    result = actions.get(choise, lambda: None)()
if __name__ =="__main__":
    main()
