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
      if ENV['SERVCERT']
        @ssl_ctx.cert = OpenSSL::X509::Certificate.new(::IO::read(ENV['SERVCERT']))
      end
      if ENV['SERVKEY']
        @ssl_ctx.key  = OpenSSL::PKey.read(::IO::read(ENV['SERVKEY']))
      end

      @ssl = OpenSSL::SSL::DTLSSocket.new(@socket, @ssl_ctx)
      self
    end

    def welcome_msg
      log.info "David #{David::VERSION} on #{RUBY_DESCRIPTION} (DTLS)"
      log.info "Starting on coaps://[#{host}]:#{port}"
    end

    def run
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
      loop do
        begin
          newsock   = ::UDPSocket.new(@af)
          #puts "newsock: #{newsock}"
          sslaccept = @ssl.accept(newsock)

          puts "SSLaccept: #{sslaccept}"

          if sslaccept
            newpeer = DtlsHandler.new(sslaccept, @ctx, self)
            newpeer.async.runone
            #newpeer.runone
            log.info "Processed, waiting for one"
          else
            log.info "waiting for traffic 1"
            Celluloid::IO.wait_readable(@ssl)
          end

        rescue ::IO::WaitReadable
          log.info "waiting for traffic 2"
          Celluloid::IO.wait_readable(@ssl)
          retry
        end
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

      (1..1).each do
        puts "Processing in #{$$}"
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

    def answer(exchange, key = nil)
      @ssl.syswrite(exchange.message.to_wire)

      if log.info?
        log.info('-> ' + exchange.to_s)
        log.debug(exchange.message.inspect)
      end

      server.cache_add(exchange.key, exchange.message) if exchange.ack?
    end

    private

    def shutdown
      if @ssl
        @ssl.sysclose
      end
    end
  end
end
