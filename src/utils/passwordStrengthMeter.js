const passwordStrengthMeter =  (password) => {
    //This password criteria have to be sent to the frontend-dev also
    const passwordCriteria = [
        { label: "At least 8 characters", met: password.length >= 8, weight: 1 },
        { label: "Contains uppercase letter", met: /[A-Z]/.test(password), weight: 1 },
        { label: "Contains lowercase letter", met: /[a-z]/.test(password), weight: 1 },
        { label: "Contains a number", met: /\d/.test(password), weight: 1 },
        { label: "Contains special character", met: /[!@#$%^&*(),.?":{}|<>]/.test(password), weight: 2 }
    ];

    const strengthScore = passwordCriteria.reduce(
        (score, criteria) => score + (criteria.met ? criteria.weight : 0), 0
    );

    const isStrongPassword = strengthScore >= 5

    //Get failed criteria for error message
    const failedCriteria = passwordCriteria.filter(criteria => !criteria.met).map(criteria => criteria.label);

    return { isStrongPassword, passwordCriteria, failedCriteria }
}

export default passwordStrengthMeter