class SearchController < ApplicationController
  def index
    query = params[:q].upcase
    render plain: query
  end
end
