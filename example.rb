require_relative 'lib/ruby-triton'

host       = ENV['SDC_URL']
account    = ENV['SDC_ACCOUNT']
#subuser      = ENV['SDC_USER']
priv_key   = ENV['SDC_KEY']

priv_key_data = File.read(priv_key)

@@client = RubyTriton::CloudApiClient.new(host, account, priv_key_data,
                                    :verify_ssl => false,
#                                    :subuser => 'monte',
                                    )

#client.list_machines().each do | instances |
#  puts instances.inspect
#end

#puts client.list_machines().count
