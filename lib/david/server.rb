require 'david/app_config'

require 'david/server/mid_cache'
require 'david/server/multicast'
require 'david/server/respond'
require 'david/server/utility'

module David
  class Server
    include Celluloid::IO

    include MidCache
    include Multicast
    include Respond
    include Utility

    attr_reader :log, :socket, :app, :mid_cache, :options
    attr_reader :host, :port

    # this should be a more complex structure that keeps track of how much
    # space has been used per-mid, and when each entry was last updated.
    # old entries should be expired on a LRU basis.
    # XXX substitute a duck-type for Hash
    cattr_accessor :blocks do Hash.new end

    finalizer :shutdown

    def setup_options(app,options)
      @app        = app.respond_to?(:new) ? app.new : app
      @mid_cache  = {}
      @options    = AppConfig.new(options)
      @log        = @options[:Log]

      @host, @port  = @options.values_at(:Host, :Port)
    end

    def welcome_msg
      log.info "David #{David::VERSION} on #{RUBY_DESCRIPTION}"
      log.info "Starting on coap://[#{@host}]:#{@port}"
    end

    def opensocket(dtls = false)
      @af = ipv6? ? ::Socket::AF_INET6 : ::Socket::AF_INET

      # Actually Celluloid::IO::UDPSocket.
      @socket = UDPSocket.new(@af)
      multicast_initialize! if @options[:Multicast]
      @socket.bind(@host, @port)
    end

    def initialize(app, options)
      setup_options(app,options)
      welcome_msg
      opensocket(false)
    end

    def run
      loop do
        if jruby_or_rbx?
          dispatch(*@socket.recvfrom(1152))
        else
          begin
            dispatch(*@socket.to_io.recvmsg_nonblock)
          rescue ::IO::WaitReadable
            Celluloid::IO.wait_readable(@socket)
            retry
          end
        end
      end
    end

    def send_con(message)
      @socket.sendmsg(exchange.message.to_wire, 0, exchange.host, exchange.port)
    end

    def answer(exchange, key = nil)
      send_reply(exchange.message.to_wire, 0, exchange.host, exchange.port)

      if log.info?
        log.info('-> ' + exchange.to_s)
        log.debug(exchange.message.inspect)
      end

      cache_add(exchange.key, exchange.message) if exchange.ack?
    end

    def send_reply(wire, thing, host, port)
      @socket.sendmsg(message, thing, host, port)
    end

    private

    def dispatch(*args)
      data, sender, _, anc = args

      if jruby_or_rbx?
        port, _, host = sender[1..3]
      else
        host, port = sender.ip_address, sender.ip_port
      end

      message  = CoAP::Message.parse(data)

      b1 = message.options[:block1]
      unless b1.nil?
        # find the CoAP Block for this MID.

        block1 = CoRE::CoAP::Block.new(message.options[:block1]).decode
        block1.data = message.payload
        @@blocks[message.mid] ||= Array.new
        @@blocks[message.mid] << block1

        log.info("<-block1[#{block1.num},#{message.mid}]- #{@@blocks[message.mid].size} received." )
        if block1.more
          m2 = message.clone
          m2.mcode = [2, 31]
          m2.tt    = :non
          if m2.tt == :con
            m2.tt    = :ack
          end

          #byebug
          log.info(" replying to block #{block1.num}")
          send_reply(m2.to_wire, 0, host, port)
          return
        else
          log.info(" (last)")

          data = ""
          # now need to assemble the blocks we got.
          blocks = @@blocks[message.mid]
          blocks.each { |b| b.assemble(data) }
          message.payload = data

          # calculate SHA256 of data for logging/debug purposes
          sha256 = Digest::SHA2.hexdigest(data)
          log.info("#{blocks.size} chunks assembled, size=#{data.size}, SHA256: " + sha256)

          # clean up cache.
          @@blocks.delete(message.mid)

          # XXX a timer needs to clean up the blocks at some interval.
        end
      end

      exchange = Exchange.new(host, port, message, anc)

      return if !exchange.non? && exchange.multicast?

      if log.info?
        log.info('<- ' + exchange.to_s)
        log.debug(message.inspect)
      end

      pong(exchange) and return if exchange.ping?

      key = exchange.key
      cached = cache_get(key)

      if exchange.response? && !cached.nil?
        cache_delete(key)
      elsif exchange.request?
        handle_request(exchange, key, cached)
      end
    end

    def handle_request(exchange, key, cached)
      if exchange.con? && !cached.nil? #&& !exchange.idempotent?
        response = cached[0]
        log.debug("dedup cache hit #{exchange.mid}")
      else
        response, _ = respond(exchange)
      end

      unless response.nil?
        exchange.message = response
        answer(exchange, key)
      end
    end

    def pong(exchange)
      exchange.message.tt = :ack
      answer(exchange)
    end

    def shutdown
      @socket.close unless @socket.nil?
    end
  end
end
