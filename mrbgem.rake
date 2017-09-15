MRuby::Gem::Specification.new('mruby-resolv') do |spec|
  spec.license = 'BSDL 2'
  spec.authors = 'keizo'
  spec.version = '0.1.0'
  spec.summary = 'Resolv class'
  ['mruby-socket', 'mruby-random'].each do |gem|
    spec.add_dependency gem
  end
end

