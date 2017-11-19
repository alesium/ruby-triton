require 'minitest/autorun'
require_relative '../../lib/ruby-triton'

class TestTriton < Minitest::Test
  @@client = nil

  def setup
    if ! @@client
      host   = ENV['SDC_URL']
      key    = ENV['SDC_KEY' ]
      account = ENV['SDC_ACCOUNT']

      unless host && key && account
        $stderr.puts 'Require SDC_URL, SDC_ACCOUNT and SDC_KEY env variables to run tests.'
        $stderr.puts 'E.g. SDC_ACCOUNT=john SDC_KEY=~/.ssh/john SDC_URL=https://us-east.manta.joyent.com bundle exec rake test'
        exit
      end

      priv_key_data = File.read(key)

      opts = {
          :verify_ssl => false
      }

      @@client =  RubyTriton::CloudApiClient.new(host, account, priv_key_data, opts)

    end

  end
 
  def test_accounts()
	current_account = @@client.get_account()
	assert_equal(account,current_account["login"])
	new_email = 'test@example.com'
	assert_equal(new_email, @@client.update_account({ :email => new_email}))
	@@client.update_account({ :email => current_account[:email]})
  end

  def test_machines()
	image='1f32508c-e6e9-11e6-bc05-8fea9e979940'
	package='6bcc505d-745f-eb20-9226-98f3d2067e71'
	machine = @@client.create_machine(image, package)
	assert_equal('provisioning', machine['state'])
        assert_equal(1, @@client.list_machines().count)
	assert_equal(machine["id"], @@client.get_machine(machine["id"])["id"])
	while @@client.get_machine(machine["id"])["state"] != "running"
		sleep 10
	end
	assert(@@client.stop_machine(machine['id']))
        while @@client.get_machine(machine["id"])["state"] != "stopped"
                sleep 10
        end
	assert(@@client.start_machine(machine['id']))
        while @@client.get_machine(machine["id"])["state"] != "running"
                sleep 10
        end
	assert(@@client.reboot_machine(machine['id']))
	sleep 10
        while @@client.get_machine(machine["id"])["state"] != "running"
                sleep 10
        end
	assert(@@client.resize_machine(machine["id"], '444e032a-852d-6f60-e3e3-e94cb18d3a4a'))
	machine_name = 'test'
	assert(@@client.rename_machine(machine["id"], machine_name))
	assert(@@client.enable_machine_firewall(machine["id"]))
	assert(@@client.disable_machine_firewall(machine["id"]))
	snap_name = 'test'
	assert(@@client.create_machine_snapshot(machine["id"], snap_name))
	sleep 10
	assert_equal(1,@@client.list_machine_snapshots(machine["id"]).count)
	while @@client.get_machine_snapshot(machine["id"], snap_name)['state'] != "created"
		sleep 10
	end
	assert(@@client.stop_machine(machine['id']))
        while @@client.get_machine(machine["id"])["state"] != "stopped"
                sleep 10
        end
	assert(@@client.start_machine_from_snapshot(machine["id"], snap_name))
	while @@client.get_machine(machine["id"])["state"] != "running"
		sleep 10
	end
	assert(@@client.delete_machine_snapshot(machine["id"], snap_name))
	while @@client.list_machine_snapshots(machine["id"]).count > 0
                sleep 10
        end
	assert(@@client.delete_machine(machine['id']))
  end

  def teardown()
	@@client.list_machines().each do | machine |
		@@client.delete_machine(machine['id'])
	end
  end

end

