def read_access():
    # For now, we'll just return a message
    return "read"

def write_access():
    # Similarly, just a message for now
    return "write"

def check_access(user_id):
    with open('acc.txt', 'r') as file:
        lines = file.readlines()
        for line in lines:
            id, access = line.strip().split()
            if id == user_id:
                if access == "read":
                    return read_access()
                elif access == "write":
                    return write_access()
    return "User not found or invalid access type."

