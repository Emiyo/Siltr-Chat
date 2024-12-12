// Create the profile slice using Redux Toolkit
const initialState = {
  isModalOpen: false,
  currentUserId: null,
  userData: null,
  loading: false,
  error: null
};

const profileSlice = window.RTK.createSlice({
  name: 'profile',
  initialState,
  reducers: {
    openModal: (state) => {
      state.isModalOpen = true;
    },
    closeModal: (state) => {
      state.isModalOpen = false;
    },
    setCurrentUserId: (state, action) => {
      state.currentUserId = action.payload;
    },
    setUserData: (state, action) => {
      state.userData = action.payload;
    },
    setLoading: (state, action) => {
      state.loading = action.payload;
    },
    setError: (state, action) => {
      state.error = action.payload;
    },
    clearProfile: (state) => {
      state.isModalOpen = false;
      state.currentUserId = null;
      state.userData = null;
      state.error = null;
    }
  }
});

// Export actions and reducer
window.profileActions = profileSlice.actions;
window.profileReducer = profileSlice.reducer;
