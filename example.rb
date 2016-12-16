require_relative 'lib/ruby-triton'

host       = ENV['SDC_URL']
account    = ENV['SDC_ACCOUNT']
#subuser      = ENV['SDC_USER']
priv_key   = ENV['SDC_KEY' ]

priv_key_data = File.read(priv_key)

client = RubyTriton::CloudApiClient.new(host, account, priv_key_data,
                                    :disable_ssl_verification => true,
#                                    :subuser => 'monte',
                                    )

client.list_machines(:name => "lala").each do | instances |
  puts instances.inspect
end
