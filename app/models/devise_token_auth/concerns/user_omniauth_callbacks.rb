module DeviseTokenAuth::Concerns::UserOmniauthCallbacks
  extend ActiveSupport::Concern

  included do
    validates :email, allow_blank: true, email: true, if: Proc.new { |u| u.provider == 'login' }
    validates_presence_of :email, unless: :username?
    validates_presence_of :uid, if: Proc.new { |u| u.provider != 'login' }
    validate :validate_username
    validates_format_of :username, with: /^[a-zA-Z0-9_\.]*$/, multiline: true
    validate :unique_email_user, on: :create
    validates_presence_of :password, on: :create
    validates_confirmation_of :password_confirmation
    validates_presence_of :password_confirmation, if: lambda {|u| u.encrypted_password_changed? }

    # keep uid in sync with email
    before_save :sync_uid
    before_create :sync_uid
  end

  protected

  # only validate unique email among users that registered by email
  def validate_username
    if User.where(email: username).exists?
      errors.add(:username, :invalid)
    end
  end

  def unique_email_user
    if provider == 'login' && self.class.where(provider: 'login', email: email).count > 0
      errors.add(:email, :taken)
    end
  end

  def sync_uid
    if provider == 'login'
      if !self.email.blank?
        self.uid = self.email
      else
        self.uid = self.username
      end
    end
  end
end
