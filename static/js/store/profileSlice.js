// Create the profile slice using Redux Toolkit
const initialState = {
  currentModal: null,
  currentUserId: null,
  userData: null,
  loading: false,
  error: null
};

const profileSlice = window.RTK.createSlice({
  name: 'profile',
  initialState,
  reducers: {
    setCurrentModal: (state, action) => {
      state.currentModal = action.payload;
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
      state.currentModal = null;
      state.currentUserId = null;
      state.userData = null;
      state.error = null;
    }
  }
});

// Export actions and reducer to window object
window.profileActions = profileSlice.actions;
window.profileReducer = profileSlice.reducer;
