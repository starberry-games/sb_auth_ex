defmodule SbAuthEx.MixProject do
  use Mix.Project

  @version "0.3.0"
  @source_url "https://github.com/yourusername/sb_auth_ex"

  def project do
    [
      app: :sb_auth_ex,
      version: @version,
      elixir: "~> 1.15",
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
      {:req, "~> 0.5"},
      {:workos, "~> 1.1"},
      {:ex_doc, "~> 0.31", only: :dev, runtime: false},
      {:postgrex, ">= 0.0.0", only: :test}
    ]
  end

  defp description do
    """
    Authentication package for Elixir/Phoenix apps using WorkOS AuthKit.
    Provides plugs, LiveView hooks, settings page, and user menu components.
    """
  end

  defp package do
    [
      maintainers: ["Samir"],
      licenses: ["All Rights Reserved"],
      links: %{"GitHub" => @source_url}
    ]
  end

  defp docs do
    [
      main: "readme",
      source_ref: "v#{@version}",
      source_url: @source_url
    ]
  end
end
