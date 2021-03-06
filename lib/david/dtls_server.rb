# coding: utf-8
require 'david/app_config'
require 'david/server'

module David
  class DtlsServer < Server
    attr_accessor :ssl, :ssl_ctx, :key, :cert, :af

    def opensocket(dtls = false)
      @af = ipv6? ? ::Socket::AF_INET6 : ::Socket::AF_INET

      # since it will be passed into OpenSSL, just use a regular socket..
      @socket = ::UDPSocket.new(@af)
      multicast_initialize! if @options[:Multicast]
      @socket.bind(@host, @port)
    end

    def initialize(app, options)
      setup_options(app, options)
      welcome_msg
      opensocket(true)

      @ssl_ctx = OpenSSL::SSL::DTLSContext.new

      cipherlist = options[:cipher_list] || ENV['CIPHER_LIST']
      @ssl_ctx.ciphers = cipherlist if cipherlist

      if ENV['SERVCERT']
        @ssl_ctx.cert = OpenSSL::X509::Certificate.new(::IO::read(ENV['SERVCERT']))
      end
      if ENV['SERVKEY']
        @ssl_ctx.key  = OpenSSL::PKey.read(::IO::read(ENV['SERVKEY']))
      end

      @ssl_ctx.verify_mode = OpenSSL::SSL::VERIFY_PEER

      # accept any certificate from the client.
      @ssl_ctx.verify_callback = Proc.new do |preverify_ok, store_ctx|
        store_ctx.error = OpenSSL::X509::V_OK
        true
      end

      @ssl = OpenSSL::SSL::DTLSSocket.new(@socket, @ssl_ctx)
      self
    end

    def welcome_msg
      log.info "David #{David::VERSION} on #{RUBY_DESCRIPTION} (DTLS)"
      log.info "Starting on coaps://[#{host}]:#{port}"
    end

    def run
      if false
      # Trap `Kill `
      Signal.trap("TERM") {
        print "SIGTERM ... received"
        Celluloid.shutdown
        exit
      }
      Signal.trap("QUIT") {
        print "SIGQUIT ... received"
        Celluloid.shutdown
        exit
      }
      end
      loop do
        begin
          newsock   = ::UDPSocket.new(@af)
          puts "waiting with newsock: #{newsock.inspect}"
          sslaccept = @ssl.accept(newsock)
          #sslaccept = @ssl.accept

          puts "SSLaccept: #{sslaccept} on #{$$}"

          if sslaccept
            newpeer = DtlsHandler.new(sslaccept, @ctx, self)
            newpeer.async.runone
            #newpeer.runone
          else
            log.info "waiting for traffic 1"
            Celluloid::IO.wait_readable(@ssl)
          end

        rescue ::IO::WaitReadable
          log.info "waiting for traffic 2"
          Celluloid::IO.wait_readable(@ssl)
          retry

        rescue OpenSSL::SSL::SSLError
          #log.info "connection from #{newsock.peeraddr} failed with #{$!.message}"
          log.info "connection failed with #{$!.message}"
        rescue
          log.info "other error from #{newsock.peeraddr}: #{$!}"
        end

        log.info "waiting for traffic 3 #{@ssl.io.inspect}"
        Celluloid::IO.wait_readable(@ssl)
      end
    end
  end

  class DtlsHandler < Server
    attr_accessor :ssl, :ssl_ctx, :server

    def initialize(child_dtls, ctx, server)
      @ssl = child_dtls
      @ssl_ctx = ctx
      @log = server.log
      @server = server
      @app    = server.app
      @mid_cache = server.mid_cache
      @options   = server.options
      self
    end

    def runone
      @ssl.sync_close = true
      @ssl.non_blocking = true
      @senderinfo = Addrinfo.new(@ssl.io.peeraddr,
                                 @af, ::Socket::SOCK_DGRAM, ::Socket::IPPROTO_UDP)

      if false
      # Trap `Kill `
      Signal.trap("TERM") {
        print "SIGTERM ... received"
        Celluloid.shutdown
        exit
      }
      Signal.trap("QUIT") {
        print "SIGQUIT ... received"
        Celluloid.shutdown
        exit
      }
      end

      #
      # this loop has to continue as long as the DTLS session is alive.
      # but it is unclear how to figure that out right now! XXX
      (1..999).each do |num|
        puts "\n#{num} processed in #{$$} on fd: #{@ssl.io.inspect}..."
        Celluloid::IO.wait_readable(@ssl)
        begin
          (packet, s_info) = @ssl.recvfrom(1500, 0)

        rescue Errno::ECONNREFUSED, EOFError => e
          # indicates socket closed
          @ssl = nil
          return

        rescue ::IO::WaitReadable
          log.info "waiting for traffic in server"
          Celluloid::IO.wait_readable(@ssl)
        end

        # packet = nil means EOF.
        return unless packet
        dispatch(packet, @senderinfo, nil, nil)
      end
      @ssl.close
      @ssl = nil
      return
    end

    def handle_request(exchange, key, cached)
      if exchange.con? && !cached.nil? #&& !exchange.idempotent?
        response = cached[0]
        log.debug("dedup cache hit #{exchange.mid}")
      else
        env       ||= basic_env(exchange)
        env[COAP_DTLS] = COAP_DTLS_SEC
        if @ssl.peer_cert
          #puts "PEER CERTIFICATE: #{@ssl.peer_cert}"
          env["SSL_CLIENT_CERT"] = @ssl.peer_cert
        else
          #puts "NO PEER CERTIFICATE"
          true
        end
        response, _ = respond(exchange, env)
      end

      unless response.nil?
        exchange.message = response
        answer(exchange, key)
      end
    end

    def send_reply(wire, thing, host, port)
      @ssl.syswrite(wire)
    end

    def answer(exchange, key = nil)
      @ssl.syswrite(exchange.message.to_wire)

      if log.info?
        log.info('-> ' + exchange.to_s)
        log.debug(exchange.message.inspect)
      end

      # do not cache error responses!
      # maybe should be configurable.
      unless exchange.message.mcode[0] == 5 || exchange.message.mcode[0] == 4
        server.cache_add(exchange.key, exchange.message) if exchange.ack?
      end
    end

    private

    def shutdown
      if @ssl
        @ssl.sysclose
      end
    end
  end
end
