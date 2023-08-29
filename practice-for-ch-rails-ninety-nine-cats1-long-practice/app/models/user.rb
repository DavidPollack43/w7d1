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
    validates :username, :session_token, presence: true, uniqueness: true
    validates :password_digest, presence: true
    validates :password, length: {minimum: 6}, allow_nil: true
    attr_reader :password

    def password=(password)
        self.password_digest = BCrypt::Password.create(password)
        @password = password
    end
    
    def is_password?(password)
        password_obj = BCrypt::Password.new(self.password_digest)
        password_obj.is_password?(password)
    end
    
    def self.find_by_credentials(username, passsword)
        user = User.find_by(username: username)
        if user && user.is_password?(passsword)
            user
        else
            nil
        end
    end
    
    def reset_session_token!
        self.session_token = SecureRandom.urlsafe_base64
        self.save!
        self.session_token
    end
    
    private
    def generate_unique_session_token
        while true
            session_token = SecureRandom.urlsafe_base64
            return session_token unless User.exists?(session_token: session_token)
        end
    end
    
    def ensure_session_token
        self.session_token ||= generate_unique_session_token
    end
    

end
