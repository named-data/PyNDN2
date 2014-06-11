
def dump(*list):
    result = ""
    l = [el if type(el) is str else repr(el) for el in list]
    return " ".join(l)
