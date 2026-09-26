// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

/**
 * @title AEraResonanceScore
 * @dev ERC-20 token representing on-chain reputation scores
 * @notice Soul-bound score token - transfers disabled except minting/burning
 */
contract AEraResonanceScore is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");
    bytes32 public constant BURNER_ROLE = keccak256("BURNER_ROLE");
    bytes32 public constant ADMIN_ADJUST_ROLE = keccak256("ADMIN_ADJUST_ROLE");

    mapping(address => uint256) private _scores;
    mapping(address => uint256) private _lastUpdate;

    event ScoreMinted(address indexed user, uint256 amount);
    event ScoreBurned(address indexed user, uint256 amount);
    event ScoreAdjusted(address indexed user, int256 adjustment, uint256 newScore);

    error ApprovalNotAllowed();
    error TransferNotAllowed();
    error InvalidAmount();
    error ScoreOverflow();
    error ScoreUnderflow();

    constructor(address aeraSafe) ERC20("AEra Resonance Score", "ARS") {
        _grantRole(DEFAULT_ADMIN_ROLE, aeraSafe);
        _grantRole(MINTER_ROLE, aeraSafe);
        _grantRole(BURNER_ROLE, aeraSafe);
        _grantRole(ADMIN_ADJUST_ROLE, aeraSafe);
    }

    /**
     * @dev Mint score tokens to a user
     * @param to Recipient address
     * @param amount Amount to mint
     */
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        if (amount == 0) revert InvalidAmount();
        
        _mint(to, amount);
        _scores[to] += amount;
        _lastUpdate[to] = block.timestamp;
        
        emit ScoreMinted(to, amount);
    }

    /**
     * @dev Burn score tokens from a user
     * @param from Address to burn from
     * @param amount Amount to burn
     */
    function burn(address from, uint256 amount) external onlyRole(BURNER_ROLE) {
        if (amount == 0) revert InvalidAmount();
        if (_scores[from] < amount) revert ScoreUnderflow();
        
        _burn(from, amount);
        _scores[from] -= amount;
        _lastUpdate[from] = block.timestamp;
        
        emit ScoreBurned(from, amount);
    }

    /**
     * @dev Admin function to adjust scores (positive or negative)
     * @param user User address
     * @param adjustment Adjustment amount (can be negative)
     */
    function adminAdjust(address user, int256 adjustment) external onlyRole(ADMIN_ADJUST_ROLE) {
        if (adjustment == 0) revert InvalidAmount();
        
        uint256 currentScore = _scores[user];
        uint256 newScore;
        
        if (adjustment > 0) {
            newScore = currentScore + uint256(adjustment);
            if (newScore < currentScore) revert ScoreOverflow();
            _mint(user, uint256(adjustment));
        } else {
            uint256 decrease = uint256(-adjustment);
            if (currentScore < decrease) revert ScoreUnderflow();
            newScore = currentScore - decrease;
            _burn(user, decrease);
        }
        
        _scores[user] = newScore;
        _lastUpdate[user] = block.timestamp;
        
        emit ScoreAdjusted(user, adjustment, newScore);
    }

    /**
     * @dev Get user's score
     * @param user User address
     * @return score Current score
     */
    function getScore(address user) external view returns (uint256) {
        return _scores[user];
    }

    /**
     * @dev Get last update timestamp for user
     * @param user User address
     * @return timestamp Last update time
     */
    function getLastUpdate(address user) external view returns (uint256) {
        return _lastUpdate[user];
    }

    // ========== SOUL-BOUND: Disable Transfers ==========

    function approve(address, uint256) public pure override returns (bool) {
        revert ApprovalNotAllowed();
    }

    function transfer(address, uint256) public pure override returns (bool) {
        revert TransferNotAllowed();
    }

    function transferFrom(address, address, uint256) public pure override returns (bool) {
        revert TransferNotAllowed();
    }

    function allowance(address, address) public pure override returns (uint256) {
        return 0;
    }

    // ========== ERC-165 Support ==========

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(ERC20, AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
