require "sinatra"
get "/" do
  "hello #{params[:name].upcase}"
end
