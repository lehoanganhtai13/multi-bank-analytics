def str2bool(s:str)->bool:
    if not s: return False
    return s.lower() == 'true'
