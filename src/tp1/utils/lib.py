from scapy.all import get_if_list

def hello_world() -> str:
    """
    Hello world function

    :return: "hello world"
    """
    return "hello world"


def choose_interface() -> str:
    """
    Return network interface and input user choice

    :return: network interface
    """
    list_interfaces = get_if_list()
    for n, inter in enumerate(list_interfaces):
        print(f"{n}. {inter}")
    while True:
        try:
            choice: int = int(input("choose interface: "))
            if choice < 0 or choice > len(list_interfaces):
                raise IndexError
            interface = list_interfaces[choice]
        except ValueError:
            print("choose interface must be an integer")
        except IndexError:
            print("integer out of range")
        else:
            return interface
