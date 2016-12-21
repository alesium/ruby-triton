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
      raise ArgumentError unless policy.is_a? String
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
      opts[:rules] = rules
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
      opts[:key] = key
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
    # Config
    ##
    # These endpoints allow you to get and set configuration values related to
    # your account.

    # Outputs configuration for your account. The configuration values that are
    # currently configurable are:
    # default_network: the network that docker containers are provisioned on.
    def get_config(opts = {})
      c = @client["#{@account}/config"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Updates configuration values for your account.
    #
    # ==== Attributes
    #
    # * +:default_network - String ID of the network used for provisioning docker containers
    def update_config(default_network, opts = {})
      raise ArgumentError unless default_network.is_a? String
      c = @client["#{@account}/config"]
      headers = gen_headers(opts)
      opts[:default_network] = default_network
      attempt(opts[:attempts]) do
        do_put(c, headers, opts)
      end

    end

    ##
    # datacenters
    ##

    # Provides a list of all datacenters this cloud is aware of.
    def list_datacenters(opts= {})
      c = @client["#{@account}/datacenters"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Gets an individual datacenter by name. Returns an HTTP redirect to
    # your client, where the datacenter url is in the Location header.
    #
    # ==== Attributes
    #
    # * +:name - String datacenter name
    def get_datacenter(name, opts = {})
      raise ArgumentError unless name.is_a? String
      c = @client["#{@account}/datacenters/#{name}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        raise InvalidArgument unless c.is_a? RestClient::Resource
        result = c.get(headers)
        raise InternalError unless result.is_a? RestClient::Response

        if result.code == 302
          return JSON.parse(result.body)
        end

        raise_error(result)
      end

    end

    ##
    # Services
    ##

    # Provides the URL endpoints for services for this datacenter. It is a
    # mapping of service name to URL endpoint.
    def list_services(opts= {})
      c = @client["#{@account}/services"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    ##
    # Images
    ##
    # An image contains the software packages that will be available on
    # newly-provisioned instance. In the case of hardware virtual machines,
    # the image also includes the operating system.

    # Provides a list of images available in this datacenter.
    # Note: Currently, Docker images are not included in this endpoint's
    # responses. You must use docker images against the docker service for this
    # datacenter.
    #
    # ==== Options
    #
    # * +:name - String	The "friendly" name for this image
    # * +:os - String	The underlying operating system for this image
    # * +:version - String	The version for this image
    # * +:public - Boolean	Filter public/private images
    # * +:state - String	Filter on image state. By default only active images are shown. Use ?state=all to list all images
    # * +:owner - String	Filter on owner UUID
    # * +:type - String	Filter on image type. The types changed in v8.0.0
    def list_images(opts= {})
      url = "#{@account}/images"
      if opts.size > 0
          url = url + '?' + URI.encode_www_form(opts)
      end
      c = @client[url]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Gets an individual image by id.
    #
    # ==== Attributes
    #
    # * +:image - String id of the image
    def get_image(image, opts = {})
      raise ArgumentError unless image.is_a? String
      c = @client["#{@account}/images/#{image}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Delete an image. Caller must be the owner of the image to delete it.
    #
    # ==== Attributes
    #
    # *+:image - String id of the image
    def delete_image(image, opts = {})
      raise ArgumentError unless image.is_a? String
      c = @client["#{@account}/images/#{policy}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end

    # Exports an image to the specified Manta path. Caller must be the owner of
    # the image, and the correspondent Manta path prefix, in order to export it.
    # Both the image manifest and the image file will be exported, and their
    # filenames will default to the following format when the specified manta
    # path is a directory
    #
    # ==== Attributes
    #
    # * +:image - String id of the image
    # * +:manta_path - String Manta path prefix used when exporting the image
    def export_image(image, manta_path, opts = {})
      raise ArgumentError unless image.is_a? String
      raise ArgumentError unless manta_path.is_a? String
      c = @client["#{@account}/images/#{image}?action=export"]
      headers = gen_headers(opts)
      opts[:manta_path] = manta_path
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Create a new custom image from an instance. The typical process is:
    #
    # 1. Customize an instance the way you want it.
    # 2. Call this method (create_image_from_machine) to create a new image.
    # 3. Repeat from step 1 if more customizations are desired with different images.
    # 4. Use the new image(s) for provisioning via create_machine.
    #
    # ==== Attributes
    #
    # * +:machine - String The prepared and stopped instance UUID from which the image is to be created
    # * +:name - String The name of the custom image, e.g. "my-image". See the IMGAPI docs for details
    # * +:version - String The version of the custom image, e.g. "1.0.0". See the IMGAPI docs for details
    #
    # ==== Options
    #
    # * +:description - String The image description
    # * +:homepage - String The image homepage
    # * +:eula - String The image eula
    # * +:acl - String The image acl
    # * +:tags - String The image tags
    def create_image_from_machine(machine, name, version, opts = {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless name.is_a? String
      raise ArgumentError unless version.is_a? String
      c = @client["#{@account}/images"]
      headers = gen_headers(opts)
      opts[:machine] = machine
      opts[:name] = name
      opts[:version] = version
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Updates metadata about an image.
    #
    # ==== Attributes
    #
    # * +:machine - String The prepared and stopped instance UUID from which the image is to be created
    #
    # ==== Options
    #
    # * +:name - String The name of the custom image, e.g. "my-image". See the IMGAPI docs for details
    # * +:version - String The version of the custom image, e.g. "1.0.0". See the IMGAPI docs for details
    # * +:description - String The image description
    # * +:homepage - String The image homepage
    # * +:eula - String The image eula
    # * +:acl - String The image acl
    # * +:tags - String The image tags
    def update_image(machine, opts = {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/images/#{image}?action=update"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    ##
    # Packages
    ##
    # Packages are named collections of resources that are used to describe the
    # dimensions of either a container or a hardware virtual machine. These
    # resources include (but are not limited to) RAM size, CPUs, CPU caps,
    # lightweight threads, disk space, swap size, and logical networks.

    # Provides a list of packages available in this datacenter.
    #
    # ==== Options
    #
    # * +:name - String	The "friendly" name for this package
    # * +:memory - Number	How much memory will by available (in MiB)
    # * +:disk - Number	How much disk space will be available (in MiB)
    # * +:swap - Number	How much swap space will be available (in MiB)
    # * +:lwps - Number	Maximum number of light-weight processes (threads) allowed
    # * +:vcpus - Number	Number of vCPUs for this package
    # * +:version - String	The version of this package
    # * +:group	- String	The group this package belongs to
    def list_packages(opts= {})
      url = "#{@account}/packages"
      if opts.size > 0
          url = url + '?' + URI.encode_www_form(opts)
      end
      c = @client[url]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end
    end

    # Gets an individual image by id.
    #
    # ==== Attributes
    #
    # * +:package - String id of the package
    def get_package(package, opts = {})
      raise ArgumentError unless package.is_a? String
      c = @client["#{@account}/packages/#{package}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    ##
    # Instances
    ##
    # Triton supports three different types of instances:
    #
    #  Docker containers. OS-virtualized instances managed through the Docker client.
    #  Infrastructure containers. More traditional OS-virtualized instances
    #   running SmartOS or more Linux distributions.
    #  Hardware-virtualized machines. Hardware-virtualized instances (KVM) for
    #   running legacy or special-purpose operating systems.
    #
    # Infrastructure and Docker containers are lightweight, offering the most
    # performance, observability and operational flexibility. Harware-virtualized
    # machines are useful for non-SmartOS or non-Linux stacks.

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
      url = "#{@account}/machines"
      # TODO fix for head query
      opts[:limit] = opts[:limit] ? MAX_LIMIT
      raise ArgumentError unless 0 < opts[:limit] && opts[:limit] <= MAX_LIMIT
      if opts.size > 0
          url = url + '?' + URI.encode_www_form(opts)
      end
      c = @client[url]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        if opts[:head]
          do_head(c, headers)
        else
          do_get(c, headers)
        end
      end
    end


    # Gets the details for an individual instance.
    #
    # Deleted instances are returned only if the instance history has not been
    # purged from Triton.
    #
    # ==== Attributes
    #
    # * +:instance - String id of the instance
    def get_instance(instance, opts = {})
      raise ArgumentError unless instance.is_a? String
      c = @client["#{@account}/instances/#{instance}"]
      headers = gen_headers(opts)
      attempt(opts[:attempts]) do
        do_get(c, headers)
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
    # ==== Attributes
    #
    # * +:image - String id of the image
    # * +:package - String id of the packge
    #
    # ==== Options
    #
    # * +:name - String	Friendly name for this instance; default is the first 8 characters of the machine id
    # * +:networks - Array	Desired networks ids, obtained from list_networks
    # * +:locality - Object[String => Array]	Optionally specify which instances the new instance should be near or far from
    # * +:metadata.$name - String	An arbitrary set of metadata key/value pairs can be set at provision time, but they must be prefixed with "metadata."
    # * +:tag.$name - String	An arbitrary set of tags can be set at provision time, but they must be prefixed with "tag."
    # * +:firewall_enabled - Boolean	Completely enable or disable firewall for this instance. Default is false

    def create_machine(image, package, opts= {})
      raise ArgumentError unless image.is_a? String
      raise ArgumentError unless package.is_a? String
      c = @client["#{@account}/machines"]
      headers = gen_headers(opts)
      opts[:image] = machine
      opts[:package] = name
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to shut down an instance. POST to the instance name with an
    # action of stop.
    #
    # You can poll on get_machine until the state is stopped.
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def stop_machine(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=stop"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to boot up an instance. POST to the instance name with an
    # action of start.
    #
    # You can poll on get_machine until the state is running.
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def start_machine(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=start"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to reboot an instance. POST to the instance name with an
    # action of reboot.
    #
    # You can poll on get_machine until the state is running.
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def reboot_machine(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=reboot"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end


    # Resize an instance to a new package (a.k.a. instance type).
    #
    # Resizing is only supported for containers (instances which are not
    # hardware virtual machines -- they have brand=kvm). Hardware virtual machines
    # cannot be resized.
    #
    # Resizing is not guaranteed to work, especially when resizing upwards in
    # resources. It is best-effort, and may fail. Resizing downwards will usually
    # succeed.
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:package - String	A package id, as returned from list_packages
    def resize_machine(machine, package, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless package.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=resize"]
      opts['package'] = package
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to rename an instance. POST to the instance id with an action
    # of rename. You must additionally include a new name for the instance.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:name - String	The new "friendly" name for this instance
    def rename_machine(machine, name, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless name.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=rename"]
      opts['name'] = name
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to enable the firewall for an instance.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def enable_machine_firewall(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=enable_firewall"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to completely disable the firewall of an instance.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def disable_machine_firewall(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}?action=disable_firewall"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Allows you to take a snapshot of an instance. Once you have one or more
    # snapshots, you can boot the instance from a previous snapshot.
    #
    # Snapshots are not usable with other instances; they are a point-in-time
    # snapshot of the current instance. Snapshots can also only be taken of
    # instances that are not of brand 'kvm'.
    #
    # Since instance instances use a copy-on-write filesystem, snapshots take up
    # increasing amounts of space as the filesystem changes over time. There is
    # a limit to how much space snapshots are allowed to take. Plan your
    # snapshots accordingly.
    #
    # You can poll on get_machine_snapshot until the state is created.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    #
    # ==== Options
    #
    # * +:name - String The name to assign to the new snapshot
    def create_machine_snapshot(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}/snapshots"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # If an instance is in the 'stopped' state, you can choose to start the
    # instance from the referenced snapshot. This is effectively a means to
    # roll back instance state.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:snapshot - String The name of the snapshot
    #
    # ==== Options
    #
    # * +:name - String The name to assign to the new snapshot
    def start_machine_from_snapshot(machine, snapshot, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless snapshot.is_a? String
      c = @client["#{@account}/machines/#{machine}/snapshots/#{snapshot}"]
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

    end

    # Lists all snapshots taken for a given instance. There are no filtration
    # parameters for this API.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    def list_machine_snapshots(machine, opts= {})
      raise ArgumentError unless machine.is_a? String
      c = @client["#{@account}/machines/#{machine}/snapshots"]
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Gets the state of the named snapshot.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:snapshot - String The name of the snapshot
    def get_machine_snapshots(machine, snapshot, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless snapshot.is_a? String
      c = @client["#{@account}/machines/#{machine}/snapshots/#{snapshot}"]
      attempt(opts[:attempts]) do
        do_get(c, headers)
      end

    end

    # Deletes the specified snapshot of an instance.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:snapshot - String The name of the snapshot
    def delete_machine_snapshot(machine, snapshot, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless snapshot.is_a? String
      c = @client["#{@account}/machines/#{machine}/snapshots/#{snapshot}"]
      attempt(opts[:attempts]) do
        do_delete(c, headers)
      end

    end

    # Allows you to update the metadata for a given instance. Note that updating
    # the metadata via CloudAPI will result in the metadata being updated in the
    # running instance.
    #
    # The semantics of this call are subtly different that the add_machine_tags
    # call -- any metadata keys passed in here are created if they do not exist,
    # and overwritten if they do.
    #
    # ==== Attributes
    #
    # * +:machine - String id of the machine
    # * +:keys - String or Json object of keys to update
    #
    # ==== Options
    #
    # * +:name - String The name to assign to the new snapshot
    def update_machine_metadata(machine, keys, opts= {})
      raise ArgumentError unless machine.is_a? String
      raise ArgumentError unless keys.is_a? String || keys.is_a? JSON
      c = @client["#{@account}/machines/#{machine}/snapshots/#{snapshot}"]
      opts['keys'] = keys
      attempt(opts[:attempts]) do
        do_post(c, headers, opts)
      end

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
