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
require 'httpclient'
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
    DEFAULT_CONNECT_TIMEOUT = 5
    DEFAULT_SEND_TIMEOUT    = 60
    DEFAULT_RECEIVE_TIMEOUT = 60
    MAX_LIMIT        = 1000
    HTTP_AGENT       = "ruby-triton/#{VERSION} (#{RUBY_PLATFORM}; #{OpenSSL::OPENSSL_VERSION}) ruby/#{RUBY_VERSION}-p#{RUBY_PATCHLEVEL}"
    HTTP_SIGNATURE   = 'Signature keyId="/%s/keys/%s",algorithm="%s",signature="%s"'

    CLOUDAPI_VERSION = 8
    ## TODO: Add this check
    #CLOUDAPI_PATH_REGEX   = Regexp.new('^/[^/]+(?:/?/$|/keys|/users|/roles|/jobs)(?:/|$)')

    ERROR_CLASSES    = [ 'AuthorizationFailed', 'AuthSchemeNotAllowed',
                         'BadRequest', 'Checksum', 'ConcurrentRequest',
                         'ContentLength', 'ContentMD5Mismatch',
                         'DirectoryDoesNotExist', 'DirectoryExists',
                         'DirectoryNotEmpty', 'DirectoryOperation',
                         'EntityExists', 'Internal', 'InvalidArgument',
                         'InvalidAuthToken', 'InvalidCredentials',
                         'InvalidDurabilityLevel', 'InvalidJob', 'InvalidKeyId',
                         'InvalidLink', 'InvalidSignature', 'InvalidJobState',
                         'JobNotFound', 'JobState', 'KeyDoesNotExist',
                         'LinkNotFound', 'LinkNotObject', 'LinkRequired',
                         'NotAcceptable', 'NotEnoughSpace', 'ParentNotDirectory',
                         'PreconditionFailed', 'PreSignedRequest',
                         'RequestEntityTooLarge', 'ResourceNotFound',
                         'RootDirectory', 'SecureTransportRequired',
                         'ServiceUnavailable', 'SourceObjectNotFound',
                         'SSLRequired', 'TaskInit', 'UploadTimeout',
                         'UserDoesNotExist', 'UserTaskError',
                         # and errors that are specific to this class:
                         'CorruptResult', 'UnknownError',
                         'UnsupportedKey' ]



    # Initialize a MantaClient instance.
    #
    # priv_key_data is data read directly from an SSH private key (i.e. RFC 4716
    # format). The method can also accept several optional args: :connect_timeout,
    # :send_timeout, :receive_timeout, :disable_ssl_verification and :attempts.
    # The timeouts are in seconds, and :attempts determines the default number of
    # attempts each method will make upon receiving recoverable errors.
    #
    # Will throw an exception if given a key whose format it doesn't understand.
    def initialize(host, user, priv_key_data, opts = {})
      raise ArgumentError unless host =~ /^https{0,1}:\/\/.*[^\/]/
      raise ArgumentError unless user.is_a?(String) && user.size > 0

      @host        = host
      @user        = user
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

      @client = HTTPClient.new
      @client.connect_timeout = opts[:connect_timeout] || DEFAULT_CONNECT_TIMEOUT
      @client.send_timeout    = opts[:send_timeout   ] || DEFAULT_SEND_TIMEOUT
      @client.receive_timeout = opts[:receive_timeout] || DEFAULT_RECEIVE_TIMEOUT
      @client.ssl_config.verify_mode = nil if opts[:disable_ssl_verification]

    end

    ##
    # Account
    ##

    def get_account(opts= {})
      url = cloudapi_url("/#{@user}")
      headers = gen_headers(opts)
      method = :get
      query_parameters = nil
      attempt(opts[:attempts]) do
        result = @client.send(method, url, query_parameters, headers)
        raise unless result.is_a? HTTP::Message

        if result.status == 200
          return JSON.parse(result.body)
        end

        raise_error(result)
      end
    end
    def get_account(opts= {})
      url = cloudapi_url("/#{@user}")
      headers = gen_headers(opts)
      method = :get
      query_parameters = nil
      attempt(opts[:attempts]) do
        result = @client.send(method, url, query_parameters, headers)
        raise unless result.is_a? HTTP::Message

        if result.status == 200
          return JSON.parse(result.body)
        end

        raise_error(result)
      end
    end

    def update_account(opts= {})
      url = cloudapi_url("/#{@user}")
      headers = gen_headers(opts)
      method = :post
      query_parameters = nil
      attempt(opts[:attempts]) do
        result = @client.send(method, url, query_parameters, headers)
        raise unless result.is_a? HTTP::Message

        if result.status == 200
          return JSON.parse(result.body)
        end

        raise_error(result)
      end
    end


    ##
    # Instances
    ##

    def list_machines(opts= {})
      url = cloudapi_url("/my/machines")
      headers = gen_headers(opts)
      query_parameters = {}

      limit = opts[:limit] || MAX_LIMIT
      raise ArgumentError unless 0 < limit && limit <= MAX_LIMIT
      query_parameters[:limit] = limit

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
        method = opts[:head] ? :head : :get
        result = @client.send(method, url, query_parameters, headers)
        raise unless result.is_a? HTTP::Message

        if result.status == 200
          return JSON.parse(result.body)
        end

        raise_error(result)
      end
    end

    # Allows you to provision an instance.
    # If you do not specify a name, CloudAPI will generate a random one for you.
    # If you have enabled Triton CNS on your account, this name will also be
    # used in DNS to refer to the new instance (and must therefore consist of
    # DNS-safe characters only).

    # Your instance will initially be not available for login (Triton must
    # provision and boot it); you can poll GetMachine for its status. When the
    # state field is equal to running, you can log in. If the instance is a
    # brand other than kvm, you can usually use any of the SSH keys managed
    # under the keys section of CloudAPI to login as any POSIX user on the OS.
    # You can add/remove keys over time, and the instance will automatically
    # work with that set.

    # If the the instance has a brand kvm, and of a UNIX-derived OS (e.g. Linux),
    # you must have keys uploaded before provisioning; that entire set of keys
    # will be written out to /root/.ssh/authorized_keys in the new instance,
    # and you can SSH in using one of those keys. Changing the keys over time
    # under your account will not affect a running hardware virtual machine in
    # any way; those keys are statically written at provisioning-time only, and
    # you will need to manually manage them on the instance itself.

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
        rescue Errno::ECONNREFUSED, HTTPClient::TimeoutError,
               CorruptResult => e
          raise e if attempt == tries
          sleep 2 ** attempt
          attempt += 1
        end
      end
    end

    # Creates a qualified user path consisting of the user and subuser if the
    # subuser is present. Otherwise, it returns the user
    def user_path
       @subuser ? "#{@user}/#{@subuser}" : @user
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

      headers = [[ 'Date',           now        ],
                 [ 'Authorization',  sig        ],
                 [ 'User-Agent',     HTTP_AGENT ],
                 [ 'Api-Version',    "~#{CLOUDAPI_VERSION}" ]]

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
      URI.encode(@host + path)
    end

    def validate_parameters(query_parameters, valid_parameters, opts)
      raise unless query_parameters.is_a? Hash
      raise unless valid_parameters.is_a? Hash
      raise unless opts.is_a? Hash
      opts.each do | key, val |
        puts "key = #{key};"
      end
    end

    # Raises an appropriate exception given the HTTP response. If a 40* is
    # returned, attempts to look up an appropriate error class and raise,
    # otherwise raises an UnknownError.
    def raise_error(result)
      raise unless result.is_a? HTTP::Message

      err   = JSON.parse(result.body)
      klass = CloudApiClient.const_get err['code']
      raise klass, err['message']
    rescue NameError, TypeError, JSON::ParserError
      raise UnknownError, result.status.to_s + ': ' + result.body
    end

  end
end
