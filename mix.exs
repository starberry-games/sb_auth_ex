defmodule SbAuthEx.MixProject do
  use Mix.Project

  @version "0.7.1"
  @source_url "https://github.com/starberry-games/sb_auth_ex"

  def project do
    [
      app: :sb_auth_ex,
      version: @version,
      elixir: "~> 1.18",
      elixirc_paths: elixirc_paths(Mix.env()),
      start_permanent: Mix.env() == :prod,
      deps: deps(),
      description: description(),
      package: package(),
      docs: docs()
    ]
  end

  def application do
    [
      extra_applications: [:logger]
    ]
  end

  defp elixirc_paths(:test), do: ["lib", "test/support"]
  defp elixirc_paths(_), do: ["lib"]

  defp deps do
    [
      {:phoenix, "~> 1.8"},
      {:phoenix_ecto, "~> 4.5"},
      {:phoenix_html, "~> 4.1"},
      {:phoenix_live_view, "~> 1.1"},
      {:ecto_sql, "~> 3.13"},
      {:jason, "~> 1.2"},
      {:workos, "~> 3.0"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:postgrex, ">= 0.0.0", only: :test}
    ]
  end

  defp description do
    """
    Authentication package for Elixir/Phoenix apps using WorkOS AuthKit.
    Provides plugs and LiveView hooks.
    """
  end

  defp package do
    [
      maintainers: ["Samir"],
      licenses: ["MIT"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "readme",
      extras: ["README.md", "CHANGELOG.md"],
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end
end
