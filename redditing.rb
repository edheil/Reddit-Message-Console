Camping.goes :Redditing
require 'rubygems'
require 'ruby_reddit_api'
require 'yaml/store'
require 'cgi'
require 'camping/session'

# MONKEY PATCHIN
class Reddit::Message; def author_name;  @author; end; end

module Redditing
  
  set :secret, "seekrit"
  # http://camping.rubyforge.org/api.html#class-Camping-Session
  include Camping::Session
  
  module Models
  end
  
  module Helpers
    def wait_next_action
      if $last_action
        time_since_last = Time.now - $last_action 
        time_till_next = $request_interval - time_since_last
        if time_till_next > 0
          sleep time_till_next
        end
      end
      $last_action = Time.now
      yield
    end

    def grab_sesscook(user, pass, http)
      req = Net::HTTP::Post.new('/api/login')
      req.form_data = { 'user' => user, 'passwd' => pass };
      resp = wait_next_action { http.request(req) }
      return resp['set-cookie'].split('; ').map{ |_| _.split('=')}.assoc('reddit_session').join('=')
    end

    def get_unread(user, pass, http)
      sesscook ||= grab_sesscook(user, pass, http)
      headers = { 'User-Agent' => 'Ed fooling with net/http', 'Cookie' => sesscook }
      resp = wait_next_action do
        http.get('/message/unread/.xml', headers)
      end

      returns = []
      respdoc = REXML::Document.new(resp.body)
      respdoc.elements.each("rss/channel/item") do | item |
        returns << item
      end
      return returns
    end

    def get_creds
      y = YAML::Store.new('.reddit_credentials.yml')
      y.transaction do | store |
        y['credentials'] ||= []
        credentials = y['credentials']
        unless y['credentials'].length > 0
          y['credentials'] << [['example-user','example-password']]
        end
        y['credentials']
      end
    end
  end

  module Controllers
    class Index < R '/'
      def get
        @credentials = @state['credentials']
        render :index
      end
    end

    class RedditLoginX < R '/reddit_login/(.*)'
      def get(user)
        @credentials = @state['credentials']
        if @credentials.assoc(user)
          @user,@password = @credentials.assoc(user)
        end
        render :reddit_login
      end
    end
    
    class CredentialsSet < R '/credentials_set'
      def get
        @credentials = @state['credentials'] || []
        p @credentials
        render :credentials_set
      end
      def post
        if @input.remove
          creds = @state['credentials'] || []
          if creds.assoc(@input.remove)
            creds.delete(creds.assoc(@input.remove))
            @state['credentials'] = creds
          end
          puts "GOT INPUT REMOVE: #{ @input.remove.inspect }"
        end
        if(@input.user and @input.user.length > 0 and
           @input.password and @input.password.length > 0 )
          creds = @state['credentials'] || []
          if creds.assoc(@input.user)
            this_cred = creds.assoc(@input.user)
            this_cred[1] = @input.password
          else
            creds << [@input.user, @input.password]
          end
          @state['credentials'] = creds
        end
        redirect CredentialsSet
      end
    end

    class Unread < R '/unread'
      def get
        @unread = {}
        @credentials = @state['credentials'] || get_creds 
        Net::HTTP.start('www.reddit.com') do | http |
          @credentials.each do | user, password |
            @unread[user] = get_unread(user, password, http)
          end
        end
        render :unread
      end
    end
  end

  module Views
    def layout
      html do
        title { "Redditing" }
        body do
          h1 { a( "Redditing", :href => R(Index) ) } 
          table do
            tr do
              td do
                p { a( "Set Credentials", :href => R(CredentialsSet)) }
                p { a( "Show Unread", :href => R(Unread)) }
              end
              td do
                self << yield
              end
            end
          end
        end
      end
    end
    
    def index
      if @credentials
        p do 
          text "Credentials are stored for "
          text @credentials.map{ | user, password | user }.join(", ")
        end
      end
    end

    def reddit_login
      h2 "Login as #{@user}?"
      form( :action => "http://www.reddit.com/post/login", 
            :method => :post, :target => '_blank') do
        input :type => 'hidden', :name => 'op', :value => 'login-main'
        input :type => 'hidden', :name => 'user', :value => @user
        input :type => 'hidden', :name => 'passwd', :value => @password
        input :type => 'checkbox', :name => 'rem', :id => "rem-login-main"
        label "remember me", :for => 'rem-login-main'
        br
        button "Login", :class => "btn",  :type => "submit"
      end
    end
    
    def credentials_set
      h1 "Credentials"
      form :action => R(CredentialsSet), :method => :post do
        fieldset do
          legend { "Credentials" }
          @credentials.each do | user, pass |
            p { 
              label do
                input :type => :checkbox, :name => "remove", :value => user
                text("remove: #{user}")
              end
            }
          end
          label do
            text "Add"
            input( :type => :text, :name => :user )
            text(" ")
            input( :type => :password, :name => :password )
          end
          input :type => :submit, :value => 'Submit'
        end
      end
    end
    
    def unread
      puts @credentials.inspect
      @credentials.each do | user,passsword |
        h1 { text(user) }
        p { a("login as #{user}....", :href => R(RedditLoginX, user) )}
        if @unread[user]
          @unread[user].each do | msg |
            div unread[user]
          end
        end
      end
    end
  end
end

def Redditing.create
  $last_action = Time.now
  $request_interval = 2.0
#   Redditing::Models.create_schema
end
