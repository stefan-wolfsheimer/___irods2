#pragma once
#include "irods_error.hpp"
#include "irods_auth_object.hpp"

#include "rcConnect.h"

// =-=-=-=-=-=-=-
// boost includes
#include <boost/shared_ptr.hpp>

namespace irods {

/// =-=-=-=-=-=-=-
/// @brief constant defining the native auth scheme string
    const std::string AUTH_PAM_INTERACTIVE_SCHEME( "pam_interactive" );

/// =-=-=-=-=-=-=-
/// @brief object for a native irods authenticaion sceheme
    class pam_interactive_auth_object : public auth_object {
        public:
            /// =-=-=-=-=-=-=-
            /// @brief Ctor
            pam_interactive_auth_object( rError_t* _r_error );
            virtual ~pam_interactive_auth_object();
            pam_interactive_auth_object( const pam_interactive_auth_object& );

            /// =-=-=-=-=-=-=-
            /// @brief assignment operator
            virtual pam_interactive_auth_object&  operator=( const pam_interactive_auth_object& );

            /// =-=-=-=-=-=-=-
            /// @brief Comparison operator
            virtual bool operator==( const pam_interactive_auth_object& ) const;

            /// =-=-=-=-=-=-=-
            /// @brief Plugin resolution operation
            virtual error resolve(
                const std::string&, // interface for which to resolve
                plugin_ptr& );      // ptr to resolved plugin

            /// =-=-=-=-=-=-=-
            /// @brief serialize object to key-value pairs
            virtual error get_re_vars( rule_engine_vars_t& );

            int verbose_level() const;
            int verbose_level(int level);
        private:
            int _verbose_level;
    }; // class pam_auth_object

/// @brief Helpful typedef
    typedef boost::shared_ptr<pam_interactive_auth_object> pam_interactive_auth_object_ptr;

}; // namespace irods
