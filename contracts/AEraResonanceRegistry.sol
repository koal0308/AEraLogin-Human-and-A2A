// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/access/AccessControl.sol";
import "./AEraIdentityNFT.sol";
import "./AEraResonanceScore.sol";

/**
 * @title AEraResonanceRegistry
 * @dev Registry for tracking interactions and follower relationships
 * @notice Records all social interactions and awards resonance
 */
contract AEraResonanceRegistry is AccessControl {
    bytes32 public constant SYSTEM_ROLE = keccak256("SYSTEM_ROLE");

    AEraIdentityNFT public immutable identityNFT;
    AEraResonanceScore public immutable resonanceScore;

    enum InteractionType {
        FOLLOW,
        LIKE,
        COMMENT,
        SHARE,
        REFERRAL
    }

    struct Interaction {
        address follower;
        address creator;
        bytes32 linkId;
        InteractionType actionType;
        uint256 weightFollower;
        uint256 weightCreator;
        uint256 timestamp;
    }

    // Storage
    Interaction[] private allInteractions;
    mapping(address => Interaction[]) private userInteractions;
    mapping(address => mapping(address => uint256)) public interactionsBetween;
    mapping(bytes32 => address) private linkCreators;
    mapping(address => uint256) public totalInteractionsOf;
    
    uint256 public totalResonanceAwarded;

    // Events
    event InteractionRecorded(
        address indexed follower,
        address indexed creator,
        bytes32 indexed linkId,
        InteractionType actionType,
        uint256 weightFollower,
        uint256 weightCreator,
        uint256 timestamp
    );

    event DashboardLinkRegistered(
        bytes32 indexed linkId,
        address indexed creator
    );

    error InvalidIdentityNFT();
    error InvalidResonanceScore();
    error InvalidWeight();
    error NoActiveIdentity();
    error LinkAlreadyRegistered();

    constructor(
        address _identityNFT,
        address _resonanceScore,
        address aeraSafe,
        address backendAddress
    ) {
        if (_identityNFT == address(0)) revert InvalidIdentityNFT();
        if (_resonanceScore == address(0)) revert InvalidResonanceScore();

        identityNFT = AEraIdentityNFT(_identityNFT);
        resonanceScore = AEraResonanceScore(_resonanceScore);

        _grantRole(DEFAULT_ADMIN_ROLE, aeraSafe);
        _grantRole(SYSTEM_ROLE, backendAddress);
        _grantRole(SYSTEM_ROLE, aeraSafe);
    }

    /**
     * @dev Register a dashboard link for a creator
     * @param linkId Unique link identifier
     * @param creator Creator's address
     */
    function registerDashboardLink(bytes32 linkId, address creator) external onlyRole(SYSTEM_ROLE) {
        if (linkCreators[linkId] != address(0)) revert LinkAlreadyRegistered();
        
        linkCreators[linkId] = creator;
        emit DashboardLinkRegistered(linkId, creator);
    }

    /**
     * @dev Record an interaction between two users
     * @param follower Follower's address
     * @param creator Creator's address
     * @param linkId Dashboard link ID
     * @param actionType Type of interaction
     * @param weightFollower Resonance weight for follower
     * @param weightCreator Resonance weight for creator
     */
    function recordInteraction(
        address follower,
        address creator,
        bytes32 linkId,
        InteractionType actionType,
        uint256 weightFollower,
        uint256 weightCreator
    ) external onlyRole(SYSTEM_ROLE) {
        // Validate that both users have active identity NFTs
        if (!identityNFT.hasActiveIdentity(follower)) revert NoActiveIdentity();
        if (!identityNFT.hasActiveIdentity(creator)) revert NoActiveIdentity();

        // Create interaction record
        Interaction memory interaction = Interaction({
            follower: follower,
            creator: creator,
            linkId: linkId,
            actionType: actionType,
            weightFollower: weightFollower,
            weightCreator: weightCreator,
            timestamp: block.timestamp
        });

        // Store interaction
        allInteractions.push(interaction);
        userInteractions[follower].push(interaction);
        userInteractions[creator].push(interaction);
        
        // Update counters
        interactionsBetween[follower][creator]++;
        totalInteractionsOf[follower]++;
        totalInteractionsOf[creator]++;
        
        // Award resonance (handled by backend via ResonanceScore contract)
        totalResonanceAwarded += weightFollower + weightCreator;

        emit InteractionRecorded(
            follower,
            creator,
            linkId,
            actionType,
            weightFollower,
            weightCreator,
            block.timestamp
        );
    }

    /**
     * @dev Get link creator by link ID
     * @param linkId Link identifier
     * @return creator Creator's address
     */
    function getLinkCreator(bytes32 linkId) external view returns (address) {
        return linkCreators[linkId];
    }

    /**
     * @dev Get all interactions for a user
     * @param user User address
     * @return interactions Array of interactions
     */
    function getUserInteractions(address user) external view returns (Interaction[] memory) {
        return userInteractions[user];
    }

    /**
     * @dev Get recent interactions (last N)
     * @param count Number of interactions to retrieve
     * @return interactions Recent interactions
     */
    function getRecentInteractions(uint256 count) external view returns (Interaction[] memory) {
        uint256 total = allInteractions.length;
        if (count > total) count = total;
        
        Interaction[] memory recent = new Interaction[](count);
        for (uint256 i = 0; i < count; i++) {
            recent[i] = allInteractions[total - count + i];
        }
        
        return recent;
    }

    /**
     * @dev Get interaction by index
     * @param index Interaction index
     * @return interaction Interaction data
     */
    function getInteraction(uint256 index) external view returns (Interaction memory) {
        require(index < allInteractions.length, "Index out of bounds");
        return allInteractions[index];
    }

    /**
     * @dev Get total number of interactions
     * @return total Total interactions count
     */
    function getTotalInteractions() external view returns (uint256) {
        return allInteractions.length;
    }

    /**
     * @dev Get user statistics
     * @param user User address
     * @return totalInteractions Total interactions
     * @return totalResonance Total resonance earned
     * @return isActive Has active identity
     */
    function getUserStats(address user) external view returns (
        uint256 totalInteractions,
        uint256 totalResonance,
        bool isActive
    ) {
        totalInteractions = totalInteractionsOf[user];
        totalResonance = resonanceScore.getScore(user);
        isActive = identityNFT.hasActiveIdentity(user);
    }

    // ========== ERC-165 Support ==========

    function supportsInterface(bytes4 interfaceId)
        public
        view
        override(AccessControl)
        returns (bool)
    {
        return super.supportsInterface(interfaceId);
    }
}
