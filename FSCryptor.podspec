Pod::Spec.new do |s|
  s.name             = 'FSCryptor'
  s.version          = '0.0.2'
  s.summary          = 'FSCryptor is a tool for show logs when app run'
  s.description      = <<-DESC
		This is a very small software library, offering a few methods to help with programming.
    DESC

  s.homepage         = 'https://github.com/fuchina/FSCryptor.git'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'fudon' => '1245102331@qq.com' }
  
  s.source           = { :git => 'https://github.com/fuchina/FSCryptor.git', :tag => s.version.to_s}

  s.ios.deployment_target = '12.0'
  
  s.source_files = 'FSCryptor/**/*'
  
  s.swift_version = '5.9'

  s.dependency   'FSKit'

  s.frameworks = 'UIKit'

end
