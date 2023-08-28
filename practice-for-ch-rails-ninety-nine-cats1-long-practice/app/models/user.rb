# == Schema Information
#
# Table name: users
#
#  id              :bigint           not null, primary key
#  username        :string           not null
#  session_token   :string           not null
#  password_digest :string           not null
#  created_at      :datetime         not null
#  updated_at      :datetime         not null
#
class User < ApplicationRecord
    before_validation :ensure_session_token
    validate :username, :session_token, presence: true, unique: true
    validate :password_digest, presence: true
    validate :password, length: {minimum: 6}, allow_nil: true
    attr_reader :password

    def password=(password)
        self.password_digest = BCrypt::password.create(password)
        @password = password
    end

    def ensure_session_token
        self.session_token ||= SecureRandom.urlsafe_base64
    end
end
