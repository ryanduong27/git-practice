def customize_data(func):
    
    def swapper(*args,**kwargs):
        raw_data, file, useOption, style = func(*args, **kwargs)
        print(raw_data, file, useOption, style)
        return raw_data+1, file, useOption+2, style #semi-final
    return swapper #final

@customize_data
def scroll_elk_data(raw_data, file, useOption, style):
    raw_data += 1
    return raw_data, file, useOption+1, style
    
scroll_elk_data(1,2,5,4)
