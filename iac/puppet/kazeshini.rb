# Puppet custom fact: /etc/puppetlabs/facter/facts.d/kazeshini.rb
# Kazeshini structured fact for Puppet Facter 4.x

require 'json'

Facter.add(:kazeshini) do
  confine :kernel => :linux
  setcode do
    out = Facter::Core::Execution.execute('/usr/local/bin/kazeshini facts --json 2>/dev/null')
    begin
      JSON.parse(out)
    rescue
      nil
    end
  end
end

