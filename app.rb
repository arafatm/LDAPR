require 'ldap'
require 'json'
require 'cgi'
require 'yaml'

class LDApr < Sinatra::Base
  configure do
    file =  "./config.yml"
    if File.exist?(file)
      yaml = YAML.load_file(file)
      set :ssl,     yaml['ssl'] || false
      set :host,    yaml['host']
      set :port,    yaml['port']
      set :basedn,  yaml['basedn']
      set :user,    yaml['user']
    end
  end

  get '/' do
    haml :index
  end

  get '/b/*' do
    content_type :json
    path = request.path_info[3..-1]
    locals = ldap_dn(path)
    locals.merge! ldap_entry(path)
    return JSON.pretty_generate(locals)
    
  end
  get '/o/*' do
    content_type :json
    path = request.path_info[3..-1]
    locals = ldap_dn(path)
    locals.merge! ldap_children(path)
    return JSON.pretty_generate(locals)
  end
  get '/v/*' do
    path = request.path_info[3..-1]
    locals = ldap_dn(path)
    locals[:attributes] = {}
    locals[:children] = {}
    locals.merge!(ldap_entry(path))
    locals.merge!(ldap_children(path))
    haml :ldap, :locals => locals
  end
  get '/s/*' do
    path = request.path_info[3..-1]
    filter = construct_filter CGI::parse(request.query_string)
    locals = ldap_dn(path)
    children = ldap_children(path, LDAP::LDAP_SCOPE_SUBTREE, filter)
    return children.to_json
  end
  get '/a/*' do
    haml :form, :locals => {:path => request.path_info[3..-1]}
  end
  post '/a/*' do
    content_type :json

    result = ldap_base(params['binddn'], 
                       LDAP::LDAP_SCOPE_ONELEVEL, 
                       params['filter'])

    return JSON.pretty_generate(result)
  end

  get '/*' do
    return request.inspect.gsub(',','<br />')
  end


  private

  def ldap_entry(path, scope = default_scope, filter = default_filter)
    locals = ldap_base(path, scope, filter)
    return locals
  end

  def ldap_children(path, scope = LDAP::LDAP_SCOPE_ONELEVEL, filter = default_filter)
    locals = ldap_base(path, scope, filter)
    return locals
  end
  def ldap_dn(path)
    locals = {}
    locals[:dn_path] = path
    locals[:dn_base] = path

    return locals
  end
  def ldap_base(base, scope = default_scope, filter = default_filter)
    locals = {}

    conn = ldap_conn
    conn.bind(user,passwd) {

      begin

        conn.search(base, scope, filter) do |attributes|
          if(scope == LDAP::LDAP_SCOPE_BASE)
            locals[:attributes] ||= {}
            attributes.to_hash.each do |k,v|
              locals[:attributes][k] = v
            end
          elsif(scope == LDAP::LDAP_SCOPE_ONELEVEL)
            locals[:children] ||= []
            locals[:children] << attributes.get_dn
          elsif(scope == LDAP::LDAP_SCOPE_SUBTREE)
            locals[:children] ||= []
            locals[:children] << attributes.get_dn
          end
        end
      rescue LDAP::ResultError
        conn.perror("ResultError")
      end
    }
    return locals

  end

  def ldap_to_route(astr)
    return astr.split(',').reverse.join('/')
  end

  def route_to_ldap(astr)
    return astr.split('/').reverse.join(',')
  end

  def ldap_conn

    if settings.ssl
      conn = LDAP::SSLConn.new(settings.host, settings.port)
      conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
      return conn
    else
      conn = LDAP::Conn.new(settings.host, settings.port)
      conn.set_option(LDAP::LDAP_OPT_PROTOCOL_VERSION, 3)
      return conn
    end

  end

  def user
    return settings.user
  end

  def passwd
    return ENV['wspasswd']
  end
  def default_filter
    return '(objectclass=*)'
  end
  def default_scope
    return LDAP::LDAP_SCOPE_BASE
  end
  def construct_filter(params)

    filter = "(&"

    params.each do |attrib, value|
      if value.length > 1
        filter += "(|"
        value.each do |v|
          filter += "(#{attrib}=#{v})"
        end
        filter += ")"
      else
        filter += "(#{attrib}=#{value[0]})"
      end
    end

    filter += ")"

    return filter
  end
end
