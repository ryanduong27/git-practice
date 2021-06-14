def display_info(func):
    def inner():
        print(f"Excuting \"{func.__name__}\" function")
        func()
        print('Done!')
    return inner

@display_info
def printer():
    print("Hello World!")
    
@display_info
def summer():
    print("Too hot!")
    
summer()