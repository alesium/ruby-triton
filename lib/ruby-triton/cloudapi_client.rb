# Copyright (c) 2016, Les Technologies Alesium, Inc. All rights reserved.
#
# ruby-triton is a simple low-abstraction layer which communicates with Joyent's
# Triton container as a service.
#
# ruby-triton should be thread-safe, and supports pooling of keep-alive
# connections to the same server (through HTTPClient). It only relies on the
# standard library and two pure Ruby libraries, so it should work anywhere.
#
# For more information about Triton and general ruby-triton usage, please see
# README.md.



require 'openssl'
require 'net/ssh'
require 'rest-client'
require 'base64'
require 'digest'
require 'time'
require 'json'
require 'cgi'
require 'uri'

require File.expand_path('../version', __FILE__)


module RubyTriton
  class CloudApiClient
    DEFAULT_ATTEMPTS        = 3
    DEFAULT_OPEN_TIMEOUT    = 20
    DEFAULT_READ_TIMEOUT    = 20
    DEFAULT_VERIFY_SSL      = OpenSSL::SSL::VERIFY_PEER

    MAX_LIMIT        = 1000
    HTTP_AGENT       = "ruby-triton/#{VERSION} (#{RUBY_PLATFORM}; #{OpenSSL::OPENSSL_VERSION}) ruby/#{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}"
    HTTP_SIGNATURE   = 'Signature keyId="/%s/keys/%s",algorithm="%s",signature="%s"'

    CLOUDAPI_VERSION = 8
    ## TODO: Add this check
    #CLOUDAPI_PATH_REGEX   = Regexp.new('^/[^/]+(?:/?/$|/keys|/users|/roles|/jobs)(?:/|$)')

    ERROR_CLASSES    = [  'BadRequest', 'InternalError', 'InUseError',
                          'InvalidArgument', 'InvalidCredentials', 'InvalidHeader',
                          'InvalidVersion', 'MissingParameter', 'NotAuthorized',
                          'RequestThrottled', 'RequestTooLarge', 'RequestMoved',
                          'ResourceNotFound', 'UnknownError']




    # Initialize a MantaClient instance.
    #
    # priv_key_data is data read directly from an SSH private key (i.e. RFC 4716
    # format). The method can also accept several optional args: :connect_timeout,
    # :send_timeout, :receive_timeout, :disable_ssl_verification and :attempts.
    # The timeouts are in seconds, and :attempts determines the default number of
    # attempts each method will make upon receiving recoverable errors.
    #
    # Will throw an exception if given a key whose format it doesn't understand.
    def initialize(host, account, priv_key_data, opts = {})
      raise ArgumentError unless host =~ /^https{0,1}:\/\/.*[^\/]/
      raise ArgumentError unless account.is_a?(String) && account.size > 0

      @host        = host
      @account     = account
      @subuser     = opts[:subuser] ? opts[:subuser] : nil

      @attempts = opts[:attempts] || DEFAULT_ATTEMPTS
      raise ArgumentError unless @attempts > 0

      if priv_key_data =~ /BEGIN RSA/
        @digest      = OpenSSL::Digest::SHA1.new
        @digest_name = 'rsa-sha1'
        algorithm    = OpenSSL::PKey::RSA
      elsif priv_key_data =~ /BEGIN DSA/
        @digest      = OpenSSL::Digest::DSS1.new
        @digest_name = 'dsa-sha1'
        algorithm    = OpenSSL::PKey::DSA
      else
        raise UnsupportedKey
      end

      @priv_key    = algorithm.new(priv_key_data)
      @fingerprint = OpenSSL::Digest::MD5.hexdigest(@priv_key.to_blob).
                                          scan(/../).join(':')


      if opts[:verify_ssl] == false
        verify_ssl = OpenSSL::SSL::VERIFY_NONE
      end
      @client = RestClient::Resource.new(@host,
                                         :open_timeout => opts[:open_timeout] || DEFAULT_OPEN_TIMEOUT,
                                         :read_timeout => opts[:read_timeout] || DEFAULT_READ_TIMEOUT,
                                         :verify_ssl => verify_ssl || DEFAULT_VERIFY_SSL
                                        )
    end

    ##
    # Account
    ##

    # You can obtain your account details and update them through CloudAPI,
    # although login cannot be changed, and password can not be retrieved.
    #
    # Retrieves your account details. Instead of providing your login name, you
    # can also provide 'my' (i.e. GET /my).
    def get_account(opts= {})
      c = @client["#{@account}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Update your account details with the given parameters.
    #
    # ==== Options
    #
    # * +:email+ - String
    # * +:companyName+ - String
    # * +:firstName -	String
    # * +:lastName - String
    # * +:address	- String
    # * +:postalCode - String
    # * +:city - String
    # * +:state	- String
    # * +:country	- String
    # * +:phone	- String
    # * +:triton_cns_enabled - Boolean
    def update_account(opts= {})
      c = @client["#{@account}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end
    end

    ##
    # Keys
    ##

    # This part of the API is the means by which you operate on your SSH/signing
    # keys. These keys are needed in order to login to instances over SSH, as
    # well as signing requests to this API.
    #
    # Currently CloudAPI supports uploads of public keys in the OpenSSH format.
    #
    # Note that while it's possible to provide a name attribute for an SSH key
    # in order to use it as a human-friendly alias, this attribute's presence is
    # optional. When it's not provided, the ssh key fingerprint will be used as
    # the name instead.
    #
    # For the following routes, the parameter placeholder :key can be replaced
    # with with either the key's name or its fingerprint. It's strongly
    # recommended to use fingerprint when possible, since the name attribute does
    # not have any uniqueness constraints.
    #
    # Lists all public keys we have on record for the specified account.
    def list_keys(opts= {})
      c = @client["#{@user_path}/keys"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Retrieves the record for an individual key.
    #
    # ==== Attributes
    #
    # * +:key	String - Public key in OpenSSH format
    def get_key(key, opts= {})
      raise ArgumentError unless key.is_a? String
      c = @client["#{@user_path}/keys/#{key}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Uploads a new OpenSSH key to Triton for use in HTTP signing and SSH.
    #
    # ==== Attributes
    #
    # * +:key	String - Public key in OpenSSH format
    #
    # ==== Options
    #
    # * +:name - String	Name for this key
    def create_key(key, opts= {})
      raise ArgumentError unless key.is_a? String
      c = @client["#{@user_path}/keys"]
      headers = gen_headers(opts)
      opts[:key] = key
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end
    end

    # Deletes a single SSH key, by name or fingerprint.
    #
    # ==== Attributes
    #
    # * +:key	String - Public key in OpenSSH format
    def delete_key(key, opts= {})
      raise ArgumentError unless key.is_a? String
      c = @client["#{@user_path}/keys/#{key}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end
    end

    ##
    # Users
    ##
    # These are users (also known as sub-users); additional users who are
    # authorized to use the same account, but are subject to the RBAC system.

    # Returns a list of an account's user objects. These have the same format
    # as the main account object.
    def list_users(opts= {})
      c = @client["#{@account}/users"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Get one user for an account.
    #
    # ==== Attributes
    #
    # * +:user	String - User name
    def get_user(user, opts = {})
      raise unless user.is_a? String
      c = @client["#{@account}/users/#{user}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Creates a new user under an account.
    #
    # ==== Attributes
    #
    # * +:email	String - (Required) Email address
    # * +:login	String - (Required) Login
    # * +:password String - (Required) Password
    #
    # ==== Options
    #
    # * +:companyName+ - String
    # * +:firstName -	String
    # * +:lastName - String
    # * +:address	- String
    # * +:postalCode - String
    # * +:city - String
    # * +:state	- String
    # * +:country	- String
    # * +:phone	- String
    def create_user(email, login, password, opts = {})
      raise ArgumentError unless email.is_a? String
      raise ArgumentError unless login.is_a? String
      raise ArgumentError unless password.is_a? String

      c = @client["#{@account}/users/#{user}"]
      headers = gen_headers(opts)
      opts[:email] = email
      opts[:login] = login
      opts[:password] = password
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Update a user's modifiable properties.
    # Note: Password changes are not allowed using this endpoint; there is an
    # additional methode (change_user_password) for password changes so it can
    # be selectively allowed/disallowed for users using policies.
    #
    # ==== Attributes
    #
    # *+:id - String
    #
    # ==== Options
    #
    # * +:email	- String
    # * +:login	- String
    # * +:password - String
    # * +:companyName+ - String
    # * +:firstName -	String
    # * +:lastName - String
    # * +:address	- String
    # * +:postalCode - String
    # * +:city - String
    # * +:state	- String
    # * +:country	- String
    # * +:phone	- String
    def update_user(id, opts = {})
      raise ArgumentError unless id.is_a? String
      c = @client["#{@account}/users/#{id}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # This is a separate rule for password changes, so different policies can
    # be used for an user trying to modify other data, or only their own password.
    #
    # ==== Attributes
    #
    # *+:user - String
    # *+:password - String
    # *+:password_confirmation - String
    def change_user_password(user, password, password_confirmation, opts = {})
      raise ArgumentError unless user.is_a? String
      raise ArgumentError unless password.is_a? String
      raise ArgumentError unless password_confirmation.is_a? String
      raise InvalidArgument unless password != password_confirmation
      c = @client["#{@account}/users/#{user}/change_password"]
      headers = gen_headers(opts)
      opts[:password] = password
      opts[:password_confirmation] = password_confirmation
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Remove a user. They will no longer be able to use this API.
    #
    # ==== Attributes
    #
    # *+:user - String
    def delete_user(user, opts = {})
      raise ArgumentError unless user.is_a? String
      c = @client["#{@account}/users/#{user}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end

    ##
    # Roles
    ##
    # Roles a sub-users can adopt when attempting to access a resource. See the RBAC section for more details.

    # Returns an array of account roles.
    def list_roles(opts= {})
      c = @client["#{@account}/roles"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Get an account role (:role) by id or name.
    #
    # ==== Attributes
    #
    # * +:role	String - id or name of the role
    def get_role(role, opts = {})
      raise unless role.is_a? String
      c = @client["#{@account}/roles/#{role}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Create a new role for your account.
    #
    # ==== Attributes
    #
    # * +:name - String (Required) The role's name
    #
    # ==== Options
    #
    # * +:policies - Array	This account's policies to be given to this role
    # * +:members	- Array	This account's user logins to be added to this role (Optional)
    # * +:default_members -	Array	This account's user logins to be added to this role and have it enabled by default (Optional)
    def create_role(name, opts = {})
      raise ArgumentError unless name.is_a? String
      c = @client["#{@account}/roles"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Modifies an account role. Anything but id can be modified.
    #
    # ==== Attributes
    #
    # *+:name - String role name or id
    #
    # ==== Options
    #
    # *+:policies	- Array	This account's policies to be given to this role (Optional)
    # *+:members	- Array	This account's user logins to be added to this role (Optional)
    # *+:default_members - Array	This account's user logins to be added to this role and have it enabled by default (Optional)
    def update_role(name, opts = {})
      raise ArgumentError unless name.is_a? String
      c = @client["#{@account}/roles/#{name}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Remove a role. :role must be the role id (a UUID).
    #
    # ==== Attributes
    #
    # *+:role - String UUID of the role
    def delete_role(role, opts = {})
      raise ArgumentError unless role.is_a? String
      c = @client["#{@account}/roles/#{role}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end

    ##
    # Role tags
    ##

    # Sets the given role tags to the provided resource path. resource_path can
    # be the path to any of the CloudAPI resources described in this document:
    # account, keys, users, roles, policies, user's ssh keys, datacenters,
    # images, packages, instances, analytics, instrumentations, firewall rules
    # and networks.
    # For each of these you can set role tags either for an individual resource
    # or for the whole group.
    #
    # ==== Attributes
    #
    # * +:resource_url - String (Required) The resource path to assign a role tags to.
    # * +:role-tag - Array (Required) Array of tags to be assigned/modified
    def create_role_tags(resource_url, role-tag, opts = {})
      raise ArgumentError unless resource_url.is_a? String
      raise ArgumentError unless role-tag.is_a? Array
      c = @client[resource_url]
      headers = gen_headers(opts)
      opts['role-tag'] = role-tag
      attempt(opts[:attempts]) do
        do_put(c, headers, opts)
      end

    end

    ##
    # Policies
    ##
    # Retrieves a list of account policies.
    def list_policies(opts= {})
      c = @client["#{@account}/policies"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Get an account policy (:policy) by id.
    #
    # ==== Attributes
    #
    # * +:policy - String id of the policy
    def get_policy(policy, opts = {})
      raise unless policy.is_a? String
      c = @client["#{@account}/policies/#{policy}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Creates a new account policy.
    #
    # ==== Attributes
    #
    # * +:name - String The policy name
    # * +:rules - One or more Aperture sentences to be added to the current policy
    #
    # ==== Options
    #
    # * +:description - String A description for this policy (Optional)
    def create_policy(name, rules, opts = {})
      raise ArgumentError unless name.is_a? String
      raise ArgumentError unless rules.is_a? Array
      c = @client["#{@account}/policies"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Updates an existing account policy. Everything but id can be modified.
    #
    # ==== Attributes
    #
    # * +:policy - String id of the policy
    #
    # ==== Options
    #
    # * +:name - String The policy name
    # * +:rules - One or more Aperture sentences to be added to the current policy
    # * +:description - String A description for this policy (Optional)
    def update_policy(policy, opts = {})
      raise ArgumentError unless name.is_a? String
      c = @client["#{@account}/policies/#{policy}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Delete an RBAC policy. :policy must be the policy id (a UUID).
    #
    # ==== Attributes
    #
    # *+:policy - String UUID of the role
    def delete_policy(policy, opts = {})
      raise ArgumentError unless policy.is_a? String
      c = @client["#{@account}/policies/#{policy}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end

    ##
    # User SSH Keys
    ##
    # See account keys for a detailed description. Only difference is the path
    # from where you can access users' keys:

    # Lists all public keys we have on record for the specified account user.
    # See list_keys.
    def list_user_keys(opts= {})
      raise unless @subuser is not nil
      c = @client["#{@account}/users/#{@subuser}/keys"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Retrieves the given key record either by fingerprint or name. See get_key.
    #
    # ==== Attributes
    #
    # * +:key - String id or fingerprint of key
    def get_user_key(key, opts = {})
      raise InvalidCredentials unless @subuser is not nil
      raise ArgumentError unless key.is_a? String
      c = @client["#{@account}/users/#{@subuser}/keys/#{key}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Creates a new key record. See create_key.
    #
    # ==== Attributes
    #
    # * +:key	- String Public key in OpenSSH format
    #
    # ==== Options
    #
    # * +:name - String	Name for this key
    def create_user_key(key, opts = {})
      raise InvalidCredentials unless @subuser is not nil
      raise ArgumentError unless key.is_a? String
      c = @client["#{@account}/users/#{@subuser}/keys"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Removes a key. See get_key.
    #
    # ==== Attributes
    #
    # *+:key - String id or fingerprint of key
    def delete_user_key(key, opts = {})
      raise InvalidCredentials unless @subuser is not nil
      raise ArgumentError unless key.is_a? String
      c = @client["#{@account}/users/#{@subuser}/keys/#{key}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end



    ##
    # Instances
    ##

    # Lists all instances we have on record for your account. If you have a large
    # number of instances, you can filter using the input parameters listed below.
    # Note that deleted instances are returned only if the instance history has
    # not been purged from Triton.
    #
    # You can paginate this API by passing in offset and limit. HTTP responses
    # will contain the additional headers x-resource-count and x-query-limit.
    # If x-resource-count is less than x-query-limit, you're done, otherwise call
    # the API again with offset set to offset + limit to fetch additional instances.
    #
    # Note that there is a opts[:method] = :head form of this API, so you can
    # retrieve the number of instances without retrieving a JSON describing the
    # instances themselves.
    #
    # ==== Options
    # *+:type -	String (deprecated) The type of instance (virtualmachine or smartmachine)
    # *+:brand - String	(v8.0+) The type of instance (e.g. lx)
    # *+:name	- String	Machine name to find (will make your list size 1, or 0 if nothing found)
    # *+:image - String	Image id; returns instances provisioned with that image
    # *+:state - String	The current state of the instance (e.g. running)
    # *+:memory - Integer	The current size of the RAM deployed for the instance (in MiB)
    # *+:tombstone - Boolean	Include destroyed and failed instances available in instance history
    # *+:limit - Number	Return a max of N instances; default is 1000 (which is also the maximum allowable result set size)
    # *+:offset - Number	Get a limit number of instances starting at this offset
    # *+:tag.$name - String	An arbitrary set of tags can be used for querying, assuming they are prefixed with "tag."
    # *+:docker	- Boolean	Whether to only list Docker instances, or only non-Docker instances, if present. Defaults to showing all instances.
    # *+:credentials -Boolean	Whether to include the generated credentials for instances, if present. Defaults to false
    def list_machines(opts= {})
      c = @client["my/machines"]
      headers = gen_headers(opts)

      limit = opts[:limit] || MAX_LIMIT
      raise ArgumentError unless 0 < limit && limit <= MAX_LIMIT
      # valid_parameters = {  'brand' => 'String',
      #                       'name' => 'String',
      #                       'image' => 'String',
      #                       'state' => 'String',
      #                       'memory' => 'Integer',
      #                       'tombstone' => 'Boolean',
      #                       'offset' => 'Integer',
      #                       'tag.' => 'String',
      #                       'docker' => 'Boolean',
      #                       'credentials' => 'Boolean'
      #                     }
      #
      # validate_parameters(query_parameters, valid_parameters, opts)

      attempt(opts[:attempts]) do
        if opts[:head]
          opts.delete(:head)
          do_head(c, headers)
        else
          do_get(c, headers)
        end
      end
    end

    # Allows you to provision an instance.
    # If you do not specify a name, CloudAPI will generate a random one for you.
    # If you have enabled Triton CNS on your account, this name will also be
    # used in DNS to refer to the new instance (and must therefore consist of
    # DNS-safe characters only).
    #
    # Your instance will initially be not available for login (Triton must
    # provision and boot it); you can poll GetMachine for its status. When the
    # state field is equal to running, you can log in. If the instance is a
    # brand other than kvm, you can usually use any of the SSH keys managed
    # under the keys section of CloudAPI to login as any POSIX user on the OS.
    # You can add/remove keys over time, and the instance will automatically
    # work with that set.
    #
    # If the the instance has a brand kvm, and of a UNIX-derived OS (e.g. Linux),
    # you must have keys uploaded before provisioning; that entire set of keys
    # will be written out to /root/.ssh/authorized_keys in the new instance,
    # and you can SSH in using one of those keys. Changing the keys over time
    # under your account will not affect a running hardware virtual machine in
    # any way; those keys are statically written at provisioning-time only, and
    # you will need to manually manage them on the instance itself.
    #
    #
    def create_machine(image, package, opts= {})

    end

    # ---------------------------------------------------------------------------
    protected

    # Executes a block. If there is a connection- or corruption-related exception
    # the block will be reexecuted up to the `tries' argument. It will sleep
    # for an exponentially-increasing number of seconds between retries.
    def attempt(tries, &blk)
      if tries
        raise ArgumentError unless tries > 0
      else
        tries ||= @attempts
      end

      attempt = 1

      while true
        begin
          return yield blk
        rescue Errno::ECONNREFUSED, RestClient::ServerBrokeConnection
          raise e if attempt == tries
          sleep 2 ** attempt
          attempt += 1
        end
      end
    end

    # Creates a qualified user path consisting of the user and subuser if the
    # subuser is present. Otherwise, it returns the user
    def user_path
       @subuser ? "#{@account}/#{@subuser}" : @account
    end

    # :m_some_header becomes "M-Some-Header"
    def symbol_to_header(header_symbol)
      header_symbol.to_s.split('_').map(&:capitalize).join('-')
    end

    # Creates headers to be given to the HTTP client and sent to the Manta
    # service. The most important is the Authorization header, without which
    # none of this class would work.
    def gen_headers(opts)
      now = Time.now.httpdate
      sig = gen_signature('date: ' + now)

      headers = { "Date" => now,
                  "Authorization" => sig,
                  "User-Agent" => HTTP_AGENT,
                  "Api-Version" => "~#{CLOUDAPI_VERSION}"
                }

      return headers
    end

    # Given a chunk of data, creates an HTTP signature which the Manta service
    # understands and uses for authentication.
    def gen_signature(data)
      raise ArgumentError unless data

      sig = @priv_key.sign(@digest, data)
      base64sig = Base64.strict_encode64(sig)

      return HTTP_SIGNATURE % [user_path, @fingerprint, @digest_name, base64sig]
    end

    # Returns a full URL for a given path to an object.
    def cloudapi_url(path)
      ## TODO: Add this check
      #raise ArgumentError unless path =~ CLOUDAPI_PATH_REGEX
      URI.encode(path)
    end

    # Raises an appropriate exception given the HTTP response. If a 40* is
    # returned, attempts to look up an appropriate error class and raise,
    # otherwise raises an UnknownError.
    def raise_error(result)
      raise unless result.is_a? RestClient::Response

      err   = JSON.parse(result.body)
      klass = CloudApiClient.const_get err['code']
      raise klass, err['message']
    rescue NameError, TypeError, JSON::ParserError
      raise UnknownError, result.status.to_s + ': ' + result.body
    end


    #
    # do_get abstraction method to GET request
    #
    def do_get(c, headers)
      raise unless c.is_a? RestClient::Resource
      result = c.get(headers)
      raise unless result.is_a? RestClient::Response

      if result.code == 200
        return JSON.parse(result.body)
      end

      raise_error(result)
    end

    #
    # do_post abstraction method to POST request
    #
    def do_post(c, headers, payload)
      raise unless c.is_a? RestClient::Resource
      result = c.post(payload.except!(:attempts), headers)
      raise unless result.is_a? RestClient::Response

      if result.code == 200
        return JSON.parse(result.body)
      end

      raise_error(result)
    end

    #
    # do_put abstraction method to PUT request
    #
    def do_put(c, headers, payload)
      raise unless c.is_a? RestClient::Resource
      result = c.put(payload.except!(:attempts), headers)
      raise unless result.is_a? RestClient::Response

      if result.code == 200
        return JSON.parse(result.body)
      end

      raise_error(result)
    end
    #
    # do_delete abstraction method to delete request
    #
    def do_delete(c, headers)
      raise unless c.is_a? RestClient::Resource
      result = c.delete(headers)
      raise unless result.is_a? RestClient::Response

      if result.code == 204
        return true
      end

      raise_error(result)
    end

    #
    # do_head abstraction method to head request
    #
    def do_head(c, headers)
      raise unless c.is_a? RestClient::Resource
      result = c.head(headers)
      raise unless result.is_a? RestClient::Response

      if result.code == 200
        return JSON.parse(result.body)
      end

      raise_error(result)
    end
    #
    # Validate input parameters
    # TODO: Not used yet.
    #
    def validate_parameters(query_parameters, valid_parameters, opts)
      raise unless query_parameters.is_a? Hash
      raise unless valid_parameters.is_a? Hash
      raise unless opts.is_a? Hash
      opts.each do | key, val |
        puts "key = #{key};"
      end
    end

  end
end
