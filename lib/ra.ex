defmodule Test2.Cloudtrax.RA do
  require Logger
  @moduledoc """
  This module will generate an RA (request authenticator) that is
  required for every cloudtrax request.
  """

  @doc """
  Given the request's RA, the reply, and the secret, it will generate
  a new RA to be added to the response.
  """
  def generate(ra, code, secret) do
    if String.length(ra) == 32 do
      decodedRA = Hexate.decode(ra)
      :crypto.hash(:md5, "#{code}#{decodedRA}#{secret}")
      |> Hexate.encode
    else
      Logger.error "Invalid RA length"
      nil
    end
  end
end
