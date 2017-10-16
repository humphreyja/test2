defmodule Test2.Cloudtrax.Responses do
  require EEx
  alias Test2.Cloudtrax.RA
  alias Test2.Cloudtrax.Password

  @moduledoc """
  This module is responsible for responding to cloudtrax in a valid format.
  """

  # Compiled Templates
  EEx.function_from_file :defp, :reject_response, "lib/responses/reject.txt", [:ra]
  EEx.function_from_file :defp, :accept_response, "lib/responses/accept.txt", [:ra, :seconds, :download, :upload]
  EEx.function_from_file :defp, :ok_response, "lib/responses/ok.txt", [:ra]

  @doc """
  Response Text to a cloudtrax reject
  """
  def reject(ra, secret) do
    reject_response(RA.generate(ra, "REJECT", secret))
  end

  @doc """
  Response Text to a cloudtrax accept
  """
  def accept(ra, secret, session_time \\ 3600, download \\ 5000, upload \\ 3000) do
    accept_response(RA.generate(ra, "ACCEPT", secret), session_time, download, upload)
  end

  @doc """
  Response Text to a cloudtrax ok
  """
  def ok(ra, secret) do
    ok_response(RA.generate(ra, "OK", secret))
  end

  @doc """
  The url of the router used to connect to the wifi.
  """
  def redirect_url(challenge, router_ip, router_port, secret, username \\ "d9b65aca", password \\ "9ca835d6271f") do
    "http://#{router_ip}:#{router_port}/logon?username=#{username}&password=#{Password.encode(password, challenge, secret)}"
  end
end
