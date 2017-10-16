defmodule Test2.Cloudtrax.Password do
  require Bitwise
  @moduledoc """
  This module is responsible for encoding the cloudtrax password.  Since we are not
  using password authentication but cloudtrax still requires something encoded gets sent,
  this module does not provide a decoding method.
  """

  @doc """
  Encodes a password using the challenge from the request and the secret
  """
  def encode(password, challenge, secret) do
    if valid_challenge(challenge) do
      challenge = pack_challenge(challenge)
      {encoded_secret, secret_length} = encoded_secret_and_length(secret, challenge)
      password = password <> "\x00"
      encoded_password = encode_password_to_list(0, password, encoded_secret, secret_length)
      Hexate.encode(encoded_password)
    end
  end

  defp encode_password_to_list(idx, password, secret, secret_length) do
    if String.length(password) > idx do
      <<a::utf8>> = String.at(password, idx)
      b = :binary.at(secret, rem(idx, secret_length))
      <<Bitwise.bxor(a, b)>> <> encode_password_to_list(idx + 1, password, secret, secret_length)
    else
      ""
    end
  end

  defp encoded_secret_and_length(secret, challenge) do
    if String.length(secret) > 0 do
      encoded_secret = :crypto.hash(:md5, "#{challenge}#{secret}")
      secret_length = 16
      {encoded_secret, secret_length}
    else
      encoded_secret = challenge
      secret_length = String.length(challenge)
      {encoded_secret, secret_length}
    end
  end

  defp pack_challenge(challenge) do
    Hexate.decode(challenge)
  end

  defp valid_challenge(challenge) do
    rem(String.length(challenge), 2) == 0
  end
end
