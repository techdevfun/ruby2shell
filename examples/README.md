# Examples

Fixture `ruby -v` outputs and app dirs used by the tests and the
demo. Provenance:

- `ruby-v-3.4.12.txt`  -  RECORDED from a real Ruby 3.4.12 built
  from the official source tarball (cache.ruby-lang.org) on this
  build machine, 20/11/2026. `ruby -v` only prints a version
  string; nothing else was run.
- `ruby-v-3.4.13.txt`, `ruby-v-3.3.14.txt`, `ruby-v-3.3.13.txt`,
  `ruby-v-4.0.9.txt`, `ruby-v-4.0.10.txt`, `ruby-v-3.2.0.txt`  - 
  REPRESENTATIVE FORMAT: the version numbers are from the Ruby
  18/11/2026 security advisory; the revision hash and date are
  format placeholders, not recorded outputs.
- `app-rails/`, `app-sinatra-classic/`, `app-rack/`,
  `app-rails-api-only/`  -  SYNTHETIC minimal app dirs (a Gemfile,
  a Gemfile.lock, a config.ru and one or two source files) built
  for the tests and the demo. They are not real apps.
- `Dockerfile-vulnerable`, `Dockerfile-fixed`  -  SYNTHETIC Dockerfiles
  (`FROM ruby:3.4.12` / `FROM ruby:3.4.13`).

Nothing in this directory is a measurement of a real machine.
