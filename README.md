mruby-resolv(v0.1.0)
====

## Descriotion

DNS low level implementation

there are only `Resolv::DNS#send` & `Resolv::DNS#recv` work well.

### Resolv::DNS#new(af)
in default, `af` is `Socket::AF_INET`

### Resolv::DNS#send(query, host, port = 53) 
@param query is a `Resolv::DNS::Query`.  
@param host is a `String` as hostname.  

### Resolv::DNS#recv
@return `DNS::Resolv::Query`

### Resolv::DNS::Query

DNS query representation
#### instance variable

- @header 
- @questions
- @answers
- @authorities
- @additionals

now, you should obtain data by yourself.


## goal

mruby-resolv is Ruby Resolv class implementation for mruby.
API is same Ruby Resolv,
and also mruby-ldns, mruby-knot.

#### notes
if you use mruby on application embeded use,
I recommend to use mruby-ldns mrbgem.
ldns is secure, well-maintaned, simple C-library.
I make ldns mruby wrapper as Resolv class.


## sample
see `/example`

## Requirement
work linux only

if you want to use other system , contirubute us.

## Install

add github path to build_config.rb 

```ruby

  conf.gem :github => "keizo042/mruby-resolv"
```

# Usage

## LICENSE
2 clause BSD L
## AUTHOR

[keizo](https://github.com/keizo042)


## Contact us
twitter : @keizo042  
mail: keizo.bookman at gmail.com  
