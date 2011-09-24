use Rack::Static, :urls => ["/public"]

require 'redditing'
run Redditing
