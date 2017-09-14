bytes = [ # Header
         0, 66,  
         1, 0, 
         0, 1, 
         0, 0, 
         0, 0, 
         0, 0, 
         # Question
         6, 103, 111, 111, 103, 108, 101, 3, 99, 111, 109, 0, 
         0, 1, 
         0, 1]


query = Resolv::DNS::Codec.new.decode(bytes)
p query

