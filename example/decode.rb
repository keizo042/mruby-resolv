bytes = [ # Header
         0, 66,  
         1, 0, 
         0, 1,  # qd
         0, 0,  # an
         0, 0,  # ns
         0, 0,  # ar
         # Question
         6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, # 6google3com0
         0, 1, 
         0, 1]


query = Resolv::DNS::Codec.new.decode(bytes)
p query
p query.header
